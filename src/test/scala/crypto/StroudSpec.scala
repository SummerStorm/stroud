package crypto

import org.scalatest._
import Crypto.{ generateIv, generateDummyIv, decryptIv, encryptAES, decryptAES }
import Stroud._
import ImplicitHelpers._

class StroudSpec extends FlatSpec with Matchers {
	val SampleSize = 100
	val random = new java.security.SecureRandom
	val plaintext: Array[Byte] = Array(0xAA.toByte, 0x22, 0xFF.toByte, 0x11, 0x22, 0x34)

	"AES" should "encrypt and decrypt correctly" in {
		val iv: Array[Byte] = generateIv(plaintext.length)
		def trial = {
			val ciphertext = Crypto.encryptAES(plaintext, iv)
			val result = Crypto.decryptAES(ciphertext, iv)
			java.util.Arrays.equals(plaintext, result)
		}
		(1 to SampleSize).forall(_ => trial) shouldBe true
	}

	"generateIv" should "generate a unique IV every time" in {
		generateIv(plaintext.length).mkString should not be generateIv(plaintext.length).mkString
	}

	"it" should "generate a 64 bit byte array" in {
		generateIv(plaintext.length).length shouldBe 8
	}

	it should "set the isPartial flag to false" in {
		val iv = generateIv(plaintext.length)
		val (ciphertextLength, protocolId, isPartial) = decryptIv(iv)
		isPartial shouldBe false
	}

	"generateDummyIv" should "generate a unique IV every time" in {
		generateDummyIv.deep should not be generateDummyIv.deep
	}

	it should "generate a 64 bit byte array" in {
		generateDummyIv.length shouldBe 8
	}

	it should "set the isPartial flag to true" in {
		val iv = generateDummyIv
		val (ciphertextLength, protocolId, isPartial) = decryptIv(iv)
		isPartial shouldBe true
	}

	"decryptIv" should "retrive the ciphertextLength" in {
		val iv = generateIv(plaintext.length)
		val (ciphertextLength, protocolId, isPartial) = decryptIv(iv)
		ciphertextLength shouldBe 16
	}

	it should "retrive the protocolId" in {
		val protocolIdOld = 23
		val iv = generateIv(plaintext.length, protocolIdOld)
		val (ciphertextLength, protocolId, isPartial) = decryptIv(iv)
		protocolId shouldBe protocolIdOld
	}

	"stringToCjkCodepoint" should "produce Array(0x609f) when given 悟" in {
		stringToCjkCodepoint("悟") shouldBe Array(0x609f)
	}

	it should "produce Array(U+609f,U+609f) when given 悟" in {
		stringToCjkCodepoint("悟悟") shouldBe Array(0x609f, 0x609f)
	}

	"cjkCodepointsToString" should "produce 悟 when given U+609f" in {
		cjkCodepointsToString(Array(0x609f)) shouldBe "悟"
	}

	it should "produce 悟悟 when given U+609f" in {
		cjkCodepointsToString(Array(0x609f, 0x609f)) shouldBe "悟悟"
	}

	"cjkCodepointsToString and stringToCjkCodepoint" should "undo each other" in {
		var input = "炒飯"
		cjkCodepointsToString(stringToCjkCodepoint(input)) shouldBe input
	}

	it should "undo each other reversed" in {
		var input = Array(0x609f, 0x609f, 0x0, 0x1, 0xffff)
		stringToCjkCodepoint(cjkCodepointsToString(input)) shouldBe input
	}

	"intToCjkCodepoint" should "throw an IllegalArgumentException when given the overflow case of 70304" in {
		a[IllegalArgumentException] should be thrownBy {
			intToCjkCodepoint(70304)
		}
	}

	it should "throw an IllegalArgumentException when given a negative input" in {
		a[IllegalArgumentException] should be thrownBy {
			intToCjkCodepoint(-1)
		}
	}

	it should "produce 19903 when given the border case 70303" in {
		intToCjkCodepoint(70303) shouldBe 19903
	}

	"CjkCodepointToInt" should "throw an IllegalArgumentException when given 'a'" in {
		a[IllegalArgumentException] should be thrownBy {
			cjkCodepointToInt("a".codePointAt(0))
		}
	}

	it should "produce 70303 when given the border case 悟" in {
		cjkCodepointToInt("悟".codePointAt(0)) shouldBe 47487
	}

	it should "produce 0 when given the border case 𠀀" in {
		cjkCodepointToInt("𠀀".codePointAt(0)) shouldBe 0
	}

	"intToString" should "work" in {
		var input = Array(0x609f, 0x609f, 0x0, 0x1, 0xffff)
		intToString(input) shouldBe "𦂟𦂟𠀀𠀁㬟"
	}

	"stringToInt" should "work" in {
		var input = "炒飯"
		stringToInt(input) shouldBe Array(51570, 61903)
	}

	"intToString and stringToInt" should "reverse each other" in {
		var input = Array(0x0, 0x1, 0xff, 0xff00, 0x00ff, 0xffff)
		stringToInt(intToString(input)) shouldBe input
	}

	it should "perform a round trip on a block 1 int" in {
		val in = 1234
		cjkCodepointToInt(intToCjkCodepoint(in)) shouldBe in
	}

	it should "perform a round trip on a block 2 int" in {
		val in = 50000
		cjkCodepointToInt(intToCjkCodepoint(in)) shouldBe in
	}

	it should "perform a round trip on a block 3 int" in {
		val in = 70000
		cjkCodepointToInt(intToCjkCodepoint(in)) shouldBe in
	}

	"bytesToInt" should "turn 0x00, 0x00 into 0" in {
		var input = Array(0x00, 0x00).map(_.toByte)
		twoBytesToInt(input) shouldBe 0
	}

	it should "turn 0x01, 0x00 into 1" in {
		var input = Array(0x01, 0x00).map(_.toByte)
		twoBytesToInt(input) shouldBe 1
	}

	it should "turn 0x00, 0x01 into 256" in {
		var input = Array(0x00, 0x01).map(_.toByte)
		twoBytesToInt(input) shouldBe 256
	}

	it should "turn 0xff, 0xff into 256" in {
		var input = Array(0xff, 0xff).map(_.toByte)
		twoBytesToInt(input) shouldBe 65535
	}

	it should "never produce negative results" in {
		val allBytes = 0x00 to 0xFF
		val inputs = (allBytes cross allBytes).map(tuple => Array(tuple._1.toByte, tuple._2.toByte))
		val results = inputs.map(twoBytesToInt(_))
		results.forall(_ >= 0) shouldBe true
	}

	"intToBytes" should "turn 0 into 0x00, 0x00" in {
		intToBytes(0) shouldBe Array(0x00, 0x00)
	}

	it should "turn 1 into 0x00, 0x00" in {
		intToBytes(1) shouldBe Array(0x01, 0x00)
	}

	it should "turn 0x00, 0x01 into 256" in {
		intToBytes(256) shouldBe Array(0x00, 0x01)
	}

	"bytesToInt and intToBytes" should "undo each other" in {
		var input = Array(0x0, 0x1, 0xff, 0xff00, 0x00ff, 0xffff)
		bytesToInt(intToBytes(input)) shouldBe input
	}

	it should "undo each other the other way around on even length inputs" in {
		var input = Array(0x0, 0x1, 0x0f, 0xff).map(_.toByte)
		intToBytes(bytesToInt(input)) shouldBe input
	}

	"bytesToString and stringToBytes" should "undo each other" in {
		var input = Array(0x0, 0x1, 0x0f, 0xff).map(_.toByte)
		stringToBytes(bytesToString(input)) shouldBe input
	}

	"RobertStroud" should "output ciphertext that's less or equal to 280 bytes" in {
		val samples = Array.fill(SampleSize)(encrypt(2, random.nextInt().toString))
		samples.forall(_.length <= 280) shouldBe true
	}

	it should "output ciphertext that contains 140 characters" in {
		val samples = Array.fill(SampleSize)(encrypt(2, random.nextInt().toString))
		samples.forall(s => s.head.codePointCount(0, s.head.length()) == 140) shouldBe true
	}

	ignore should "encrypt and decrypt protocol 0 correctly" in {
		def trial = {
			val protocolId = 0
//			val plaintext = random.nextLong
			val plaintext = random.nextLong.toString
			val ciphertext = encrypt(protocolId, plaintext)
			val (newProtocolId, result) = decrypt(ciphertext)
			plaintext == result
		}
		(1 to SampleSize).forall(_ => trial) shouldBe true
	}

	ignore should "encrypt and decrypt protocol 1 correctly" in {
		def trial = {
			val protocolId = 1
			//			val plaintext = random.nextLong().toHexString.getBytes()
			//			val plaintext = "aaaa".getBytes()
//			val plaintext = Array(0x0, 0x1, 0x0f, 0xff).map(_.toByte)
			val plaintext = Array(0x0, 0x1, 0x0f, 0xff).map(_.toByte).toString

			val ciphertext = encrypt(protocolId, plaintext)
			val (newProtocolId, result) = decrypt(ciphertext)
			plaintext sameElements result.asInstanceOf[Array[Byte]]
		}
		(1 to SampleSize).forall(_ => trial) shouldBe true
	}

	it should "encrypt and decrypt protocol 2 correctly" in {
		def trial = {
			val protocolId = 2
			val plaintext = random.nextLong().toHexString
			val ciphertext = encrypt(protocolId, plaintext)
			val (newProtocolId, result) = decrypt(ciphertext)
			plaintext == result
		}
		(1 to SampleSize).forall(_ => trial) shouldBe true
	}

	it should "encrypt and decrypt protocol 2 long string correctly" in {
		def trial = {
			val protocolId = 2
			val plaintext = "j23x89onb7e289hxej2389hje2893hnc892h23ej23x89onb7e289hxej2389hje2893hnc892h23ej23x89onb7e289hxej2389hje2893hnc892h23ej23x89onb7e289hxej2389hje2893hnc892h23ej23x89onb7e289hxej2389hje2893hnc892h23ej23x89onb7e289hxej2389hje2893hnc892h23e".getBytes().toHex
			val ciphertext = encrypt(protocolId, plaintext)
			val (newProtocolId, result) = decrypt(ciphertext)
			plaintext == result
		}
		(1 to 2).forall(_ => trial) shouldBe true
	}
}
