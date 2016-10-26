name := "stroud"
 
version := "0.0.1"

scalaVersion := "2.11.8"
 
testOptions in Test += Tests.Argument("-oF")

libraryDependencies += "org.scalatest" % "scalatest_2.11" % "2.1.7"
