# edge-token-signing

![European Regional Development Fund](https://github.com/e-gov/RIHA-Frontend/raw/master/logo/EU/EU.png "European Regional Development Fund - DO NOT REMOVE THIS IMAGE BEFORE 05.03.2020")

 * License: LGPL 2.1
 * &copy; Estonian Information System Authority
 * [Architecture of ID-software](http://open-eid.github.io)

## Building
[![Build Status](https://ci.appveyor.com/api/projects/status/github/open-eid/edge-token-signing?branch=master&svg=true)](https://ci.appveyor.com/project/open-eid/edge-token-signing)

 1. Install dependencies from
   * [Visual Studio Community 2015](https://www.visualstudio.com/vs/community/)

 2. Fetch the source

        git clone --recursive https://github.com/open-eid/edge-token-signing
        cd edge-token-signing

 3. Build

        nuget restore
        make-package.bat

 4. Usage

        PowerShell: Add-AppxPackage Package\TokenSigning.Appx
        Open Edge and use site with client certificate requirement.

## Support
Official builds are provided through official distribution point [installer.id.ee](https://installer.id.ee). If you want support, you need to be using official builds. Contact our support via [www.id.ee](http://www.id.ee) for assistance.

Source code is provided on "as is" terms with no warranty (see license for more information). Do not file Github issues with generic support requests.
