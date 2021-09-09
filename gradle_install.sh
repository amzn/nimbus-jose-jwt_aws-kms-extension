#!/bin/bash

GRADLE_BIN_FOLDER=~/opt/gradle/gradle-7.2/bin
GRADLE_ZIP_FILE=~/opt/gradle/gradle-7.2-bin.zip

if [[ ! -d "$GRADLE_BIN_FOLDER" ]]; then
  echo '****************************************************'
  echo 'Installing Gradle version 7.2'
  echo '****************************************************'
  mkdir -p ~/opt/gradle
  wget -q https://services.gradle.org/distributions/gradle-7.2-bin.zip -O "$GRADLE_ZIP_FILE"
  yes | unzip "$GRADLE_ZIP_FILE" -d ~/opt/gradle
else
  echo '****************************************************'
  echo 'Gradle version 7.2 already installed. Skipping reinstallation.'
  echo '****************************************************'
fi

echo 'Setting path for Gradle version 7.2.'
export PATH=$GRADLE_BIN_FOLDER:$PATH
gradle -v
