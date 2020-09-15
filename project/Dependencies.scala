import sbt._

// The objects here are made available in all build.sbt files,
// that is,  <root>/.build.sbt  and  modules/{ty-core,ty-dao-rdb}/build.sbt.
//
// So can change version numbers of dependencies here, at just one place.

object ProjectDirectory {
  val versionFileContents = {
    // [Scala_213] Using(...) { ... }
    val source = scala.io.Source.fromFile("version.txt")
    try source.mkString.trim
    finally source.close()
  }
}

object Dependencies {

  object Play {
    val json = "com.typesafe.play" %% "play-json" % "2.8.1"
  }

  object Libs {
    // See: https://mvnrepository.com/artifact/org.postgresql/postgresql/
    // Upgr to: 42.2.14?
    //   https://github.com/pgjdbc/pgjdbc#maven-central
    //   https://github.com/pgjdbc/pgjdbc/blob/master/CHANGELOG.md
    //   Cool:  cancelQuery()  https://github.com/pgjdbc/pgjdbc/pull/1157
    //          e.g. stop bg queries that turns out weren't needed.
    //   supports Pg 11, 12.
    // Or switch to: https://github.com/impossibl/pgjdbc-ng/
    // supports listener-notify.
    // https://stackoverflow.com/questions/21632243/
    //        how-do-i-get-asynchronous-event-driven-listen-notify-support-in-java-using-a-p
    val postgresqlJbcdClient = "org.postgresql" % "postgresql" % "42.2.4"

    // Database migrations.
    val flywaydb = "org.flywaydb" % "flyway-core" % "5.0.7"

    val guava = "com.google.guava" % "guava" % "28.2-jre"

    val rediscala = "com.github.etaty" %% "rediscala" % "1.9.0"

    val apacheCommonsEmail = "org.apache.commons" % "commons-email" % "1.5"
    val apacheTika = "org.apache.tika" % "tika-core" % "1.18"    // for username .ext test, sync w core [5AKR20]

    val jsoup = "org.jsoup" % "jsoup" % "1.13.1"   // newest as of 2020-06

    // OAuth lib, also works for OIDC (OpenID Connect).
    // VENDOR_THIS — it'd be good to Maven-build via Makefile?
    val scribeJava = "com.github.scribejava" % "scribejava-apis" % "6.9.0"

    // Not v 3.1.2?
    val scalactic = "org.scalactic" %% "scalactic" % "3.1.1"
    val scalaTest = "org.scalatest" %% "scalatest" % "3.1.1" % "test"
    val scalaTestPlusPlay = "org.scalatestplus.play" %% "scalatestplus-play" % "3.1.2" % Test

    // Don't use, migrate to ScalaTest instead, some day.
    val specs2 = "org.specs2" %% "specs2-core" % "3.9.4" % "test"
  }

}
