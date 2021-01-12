# nat-type-identifier

## Overview

A JS-based Network Address Transalation (NAT) type identifier based on the PyStun implementation originally written by gaohawk (see: https://pypi.org/project/pystun/) which follows RFC 3489 https://www.ietf.org/rfc/rfc3489.txt.

The return of execution will return the NAT type in use by the system running the program, the returned type will be one of the following:

```
- Blocked
- Open Internet
- Full Cone
- Symmetric UDP Firewall
- Restric NAT
- Restric Port NAT
- Symmetric NAT
```

## Features

To ensure the most reliable result, the program executes a number of tests which each determine the NAT type before a mode is selected from the list of results based on the most probable type. This is because issues might occur where occassional UDP packets fail to deliver.

## Usage

```
const getNatType = require("nat-type-identifier");

// Parameters default to following listed below
return getNatType({ logsEnabled: true, sampleCount: 20, stunHost: "stun.sipgate.net" });

```

## Installation

`npm install -g nat-type-identifier`

## License

```
Copyright (c) 2021 Jeff W. Hughes MIT Licensed

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```
