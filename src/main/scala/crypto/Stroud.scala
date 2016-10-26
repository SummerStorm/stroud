//
// Stroud is a lightweight Scala library that encrypts arbitrary data and encodes them into kanji characters 
// for transmission over Twitter. Since Twitter has a 140-character limit, using ASCII characters would 
// be very inefficient. By using kanji characters we can encode exactly 280 bytes per tweet. 
//

package crypto

import ImplicitHelpers._

// requires "commons-codec" % "commons-codec" % "1.6"


object Stroud {
	//	import scala.pickling._
	//	import scala.pickling.binary._
	//	import scala.pickling.SPickler

	final val random = new scala.util.Random(new java.security.SecureRandom())

	private final val IvLength = 8
	private final val CiphertextLength = 272
	private final val TweetLength = IvLength + CiphertextLength

	def encrypt(protocolId: Int, in: String): List[String] = {
		val plaintext =
			protocolId match {
				//				case 0 => in.pickle.value // Long
				//				case 1 => in.pickle.value // Byte array
				case 2 => in.asInstanceOf[String].getBytes("UTF-8") // String
				case _ => throw new UnsupportedOperationException("Invalid protocolId: " + protocolId)
			}
		if (plaintext.length < CiphertextLength)
			encryptOneTweet(protocolId, plaintext)
		else
			encryptMultipleTweets(protocolId, plaintext)
	}

	def encryptOneTweet(protocolId: Int, plaintext: Array[Byte]): List[String] = {
		val iv = Crypto.generateIv(plaintext.length, protocolId)
		val ciphertext = Crypto.encryptAES(plaintext, iv)
		List(packTweet(iv, ciphertext))
	}

	def encryptMultipleTweets(protocolId: Int, plaintext: Array[Byte]): List[String] = {
		// The tailIv is the "true" IV, all other IVs are dummies only used to carry the isPartial flag
		val lastIv = Crypto.generateIv(plaintext.length % CiphertextLength, protocolId)
		// First encrypt using the tailIv
		val ciphertext = Crypto.encryptAES(plaintext, lastIv)

		// Then split into groups
		val groups = ciphertext.grouped(CiphertextLength).toList

		// Then process all full groups
		val fullTweets = groups.dropRight(1).map(packTweet(Crypto.generateDummyIv, _))

		// Next process the last tweet
		val lastTweet = packTweet(lastIv, groups.last)

		// Combine results and return 
		fullTweets :+ lastTweet
	}

	def decrypt(tweets: List[String]): (Int, Any) =
		if (tweets.length == 1)
			decryptOneTweet(tweets.head)
		else
			decryptMultipleTweets(tweets)

	def decryptOneTweet(tweet: String) = {
		val (protocolId, ciphertext, iv) = decryptHelper(tweet)
		val plaintext = Crypto.decryptAES(ciphertext, iv)
		processProtocol(protocolId, plaintext)
	}

	def decryptMultipleTweets(tweets: List[String]) = {
		// First handle the last tweet
		val (protocolId, finalCiphertext, finalIv) = decryptHelper(tweets.last)

		// Then handle the partial ones
		val (ivs, tails) = tweets.dropRight(1).map(unpackTweet _).unzip

		// check the ivs for isPartial
		if (ivs.exists(!Crypto.decryptIv(_)._3))
			throw new IllegalArgumentException("Invalid isPartialList ")

		// Now construct the complete ciphertext and decrypt it
		val plaintext = Crypto.decryptAES(tails.reduce(_ ++ _) ++ finalCiphertext, finalIv)
		processProtocol(protocolId, plaintext)
	}

	def processProtocol(protocolId: Int, plaintext: Array[Byte]) = {
		val data =
			protocolId match {
				//				case 0 => BinaryPickle(plaintext).unpickle[Long]
				//				case 1 => BinaryPickle(plaintext).unpickle[Array[Byte]]
				case 2 => new String(plaintext, "UTF-8")
				case _ => throw new UnsupportedOperationException("Invalid protocolId: " + protocolId)
			}
		(protocolId, data)
	}

	def decryptHelper(tweet: String) = {
		val (iv, tail) = unpackTweet(tweet)
		val (cipherTextLength, protocolId, isPartial) = Crypto.decryptIv(iv)
		assert(!isPartial)
		val ciphertext = tail.slice(0, cipherTextLength)
		(protocolId, ciphertext, iv)
	}

	def packTweet(iv: Array[Byte], ciphertext: Array[Byte]): String = {
		val padding = new Array[Byte](CiphertextLength - ciphertext.length)
		random.nextBytes(padding)

		val bytes = iv ++ ciphertext ++ padding
		assert(bytes.length == TweetLength)
		bytesToString(bytes)
	}

	def unpackTweet(tweet: String): (Array[Byte], Array[Byte]) = {
		val bytes = stringToBytes(tweet)
		bytes.splitAt(IvLength)
	}

	// ========= bytes <-> int layer =========
	def bytesToString(bytes: Array[Byte]) = {
		assert(bytes.length % 2 == 0)
		intToString(bytesToInt(bytes))
	}

	def stringToBytes(s: String) = {
		intToBytes(stringToInt(s))
	}

	def bytesToInt(bytes: Array[Byte]) = bytes.grouped(2).map(twoBytesToInt _).toArray
	def twoBytesToInt(bytes: Array[Byte]): Int = java.nio.ByteBuffer.wrap(Array(0x00.toByte, 0x00.toByte) ++ bytes.reverse).getInt()

	def intToBytes(int: Array[Int]): Array[Byte] = int.map(intToBytes _).flatten.toArray
	def intToBytes(int: Int): Array[Byte] = Array((int & 0xFF).toByte, ((int & 0xFF00) >> 8).toByte)

	// ========= int <-> codepoints layer =========
	def intToString(x: Array[Int]) = cjkCodepointsToString(intToCjkCodepoint(x))
	def stringToInt(s: String) = cjkCodepointToInt(stringToCjkCodepoint(s))

	// (0x20000, 0x2A6DF), # Block1, Kanji (CJK Extension B) 42720
	// (0x4E00, 0x9FFF), # Block2, Kanji (Unified) 20992
	// (0x3400, 0x4DBF), # Block3, Kanji (CJK Extension A) 6592 
	private final val Block1End = 42720
	private final val Block2End = 42720 + 20992
	private final val Block3End = 42720 + 20992 + 6592
	private final val Block1Offset = 0x20000
	private final val Block2Offset = 0x4E00
	private final val Block3Offset = 0x3400

	def intToCjkCodepoint(x: Array[Int]): Array[Int] = x.map(intToCjkCodepoint _)
	def intToCjkCodepoint(x: Int): Int = x match {
		case x if x < 0 => throw new IllegalArgumentException("x cannot be negative.")
		case x if x < Block1End => x + Block1Offset
		case x if x < Block2End => x - Block1End + Block2Offset
		case x if x < Block3End => x - Block2End + Block3Offset
		case _ => throw new IllegalArgumentException("x = " + x + " which is larger than Block3Offset at " + Block3End)
	}

	def cjkCodepointToInt(codepoints: Array[Int]): Array[Int] = codepoints.map(cjkCodepointToInt _)
	def cjkCodepointToInt(codepoint: Int): Int =
		codepoint match {
			case x if x >= Block1Offset && x <= 0x2A6DF => x - Block1Offset
			case x if x >= Block2Offset && x <= 0x9FFF => x - Block2Offset + Block1End
			case x if x >= Block3Offset && x <= 0x4DBF => x - Block3Offset + Block2End
			case _ => throw new IllegalArgumentException("Illegal codepoint " + codepoint + " found.")
		}

	// ========= codepoints <-> string layer =========
	def cjkCodepointToString(codePoint: Int) = new String(Character.toChars(codePoint))
	def cjkCodepointsToString(x: Array[Int]) = x.map(cjkCodepointToString _).mkString

	def stringToCjkCodepoint(s: String, idx: Int = 0, found: Array[Int] = Array()): Array[Int] = {
		if (idx >= s.length) found
		else {
			val point = s.codePointAt(idx)
			stringToCjkCodepoint(s, idx + java.lang.Character.charCount(point), found ++ Array(point))
		}
	}

	def randomTweet = {
		val dummy = new Array[Byte](TweetLength)
		random.nextBytes(dummy)
		bytesToString(dummy)
	}
}

object Crypto {
	import javax.crypto.spec.SecretKeySpec
	import javax.crypto.Cipher
	import javax.crypto.spec.IvParameterSpec
	import java.nio.ByteBuffer

	private final val AesBlockSize = 16
	private final val SecretKey = javax.xml.bind.DatatypeConverter.parseHexBinary("e233fb87e25dfd0e75a2752f4e6cead2")
	private final val AesKeySpec = new SecretKeySpec(SecretKey, "AES")
	private final val BlowfishKeySpec = new SecretKeySpec(SecretKey, "Blowfish")
	final val random = new scala.util.Random(new java.security.SecureRandom())

	// Takes in a 64 bit IV.
	def encryptAES(bytes: Array[Byte], iv: Array[Byte]) = aesCipher(Cipher.ENCRYPT_MODE, bytes, iv)
	def decryptAES(bytes: Array[Byte], iv: Array[Byte]) = aesCipher(Cipher.DECRYPT_MODE, bytes, iv)

	private def aesCipher(operation: Int, bytes: Array[Byte], iv: Array[Byte]): Array[Byte] = {
		val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
		cipher.init(operation, AesKeySpec, new IvParameterSpec(iv ++ iv))
		cipher.doFinal(bytes)
	}

	private def encryptBlowfish(bytes: Array[Byte]) = blowfishCipher(Cipher.ENCRYPT_MODE, bytes)
	private def decryptBlowfish(bytes: Array[Byte]) = blowfishCipher(Cipher.DECRYPT_MODE, bytes)

	private def blowfishCipher(operation: Int, bytes: Array[Byte]) = {
		val cipher = Cipher.getInstance("Blowfish/ECB/NoPadding")
		cipher.init(operation, BlowfishKeySpec)
		cipher.doFinal(bytes)
	}

	def generateDummyIv = {
		val base = random.nextLong() | 1l << 63
		encryptBlowfish(longToBytes(base))
	}

	def generateIv(plaintextLength: Int, protocolId: Int = 0) = {
		assert(protocolId >= 0 && protocolId < 64)
		val aesBlocks = plaintextLength / AesBlockSize + 1
		var base = System.currentTimeMillis() | aesBlocks.toLong << 58 // append aesBlocks at 58
		base = base | protocolId.toLong << 52 // append protocolId at 52
		encryptBlowfish(longToBytes(base))
	}

	def decryptIv(iv: Array[Byte]) = {
		val base = bytesToLong(decryptBlowfish(iv))
		val aesBlocks = base >> 58 & 0x1f //0x00011111
		val protocolId = base >> 52 & 0x3f //0x00111111
		val isPartial = (base >> 63 & 1l) == 1
		(aesBlocks.toInt * AesBlockSize, protocolId.toInt, isPartial)
	}

	private def bytesToLong(b: Array[Byte]) = ByteBuffer.wrap(b).getLong
	private def longToBytes(l: Long) = ByteBuffer.allocate(8).putLong(l).array()

	private def bytesToInt(b: Array[Byte]) = ByteBuffer.wrap(b).getInt()
	private def intToBytes(i: Int) = ByteBuffer.allocate(4).putInt(i).array()
}

object Main extends App {
}

object ImplicitHelpers {
	implicit class Crossable[X](xs: Traversable[X]) {
		def cross[Y](ys: Traversable[Y]) = for { x <- xs; y <- ys } yield (x, y)
	}

	implicit class toHexString(buf: Array[Byte]) {
		def toHex = buf.map("%02X" format _).mkString

		final private val md = java.security.MessageDigest.getInstance("SHA-256")

		def toHash = new sun.misc.BASE64Encoder().encode(md.digest(buf))
	}
}

