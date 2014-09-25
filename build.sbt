import com.typesafe.sbt.SbtNativePackager._
import NativePackagerKeys._

scalaVersion := "2.11.2"

version := "0.1.0-SNAPSHOT"

libraryDependencies ++= Seq(
	"com.typesafe.akka" % "akka-stream-experimental_2.11" % "0.7",
	"org.bouncycastle" % "bcprov-jdk15on" % "1.51",
	"org.json4s" %% "json4s-jackson" % "3.2.10",
	"org.apache.commons" % "commons-lang3" % "3.3.2",
	"joda-time" % "joda-time" % "2.4",
	"org.joda" % "joda-convert" % "1.2",
	"org.scalatest" %% "scalatest" % "2.2.1" % "test",
	"org.scalacheck" %% "scalacheck" % "1.11.5" % "test",
	"junit" % "junit" % "4.11" % "test"
	)

lazy val root = Project("spvwallet", file("."), settings = Defaults.defaultSettings)

packageArchetype.java_application