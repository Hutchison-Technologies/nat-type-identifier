const dgram = require("dgram");
const binascii = require("binascii");
const cryptoRandomString = require("crypto-random-string");

// Types for a STUN message
const BindRequestMsg = "0001";

const msgTypes = {
  "0001": "BindRequestMsg",
  "0101": "BindResponseMsg",
  "0111": "BindErrorResponseMsg",
  "0002": "SharedSecretRequestMsg",
  "0102": "SharedSecretResponseMsg",
  "0112": "SharedSecretErrorResponseMsg",
};

const stunAttributes = {
  MappedAddress: "0001",
  ResponseAddress: "0002",
  ChangeRequest: "0003",
  SourceAddress: "0004",
  ChangedAddress: "0005",
};

// NAT Types
const BLOCKED = "Blocked";
const OPEN_INTERNET = "Open Internet";
const FULL_CONE = "Full Cone";
const SYMMETRIC_UDP_FIREWALL = "Symmetric UDP Firewall";
const RESTRICTED_NAT = "Restric NAT";
const RESTRICTED_PORT_NAT = "Restric Port NAT";
const SYMMETRIC_NAT = "Symmetric NAT";
const ERROR = "Error";

// Response Attributes
const EXT_IP = "ExternalIP";
const EXT_PORT = "ExternalPort";
const SRC_IP = "SourceIP";
const SRC_PORT = "SourcePort";
const CHANGED_IP = "ChangedIP";
const CHANGED_PORT = "ChangedPort";
const RESP = "Resp";

const CHANGE_ADDR_ERR = "Error occurred during Test on Changed IP and Port";
const LOGS_ACTIVE = "LOGS-ACTIVE";

const sourceIp = "0.0.0.0";
const sourcePort = 54320;

const settings = [];
const backgroundOps = [];
const transactionIds = [];

const defaultStunHost = "stun.sipgate.net";
const defaultSampleCount = 20;
const sampleCountEventListenerMultiplier = 50;

/* 
   #######################
   Generic/Re-Used Methods
   #######################
*/

function pad(num, size) {
  num = num.toString();
  while (num.length < size) num = "0" + num;
  return num;
}

function bytesToStr(bytes) {
  return `${pad(bytes[0].toString(16), 2)}${
    !!bytes[1] ? pad(bytes[1].toString(16), 2) : ""
  }`;
}

function bytesValToMsgType(bytes) {
  return msgTypes[`${bytesToStr(bytes)}`];
}

function convertToHexBuffer(text) {
  return Buffer.from(binascii.a2b_hex(text).toUpperCase());
}

function hexValToInt(hex) {
  return parseInt(Number(`0x${hex}`), 10);
}

function getModeFromArray(array) {
  var modeMap = {};
  var modeElement = array[0],
    maxCount = 1;

  if (array.length == 0) {
    return null;
  }

  for (var i = 0; i < array.length; i++) {
    var elem = array[i];
    modeMap[elem] == null ? (modeMap[elem] = 1) : modeMap[elem]++;
    if (modeMap[elem] > maxCount) {
      modeElement = elem;
      maxCount = modeMap[elem];
    }
  }
  return modeElement;
}

/* 
   #########################
   Main Methods
   #########################
*/

const getIpInfo = async ({ stunHost, stunPort = 3478 }, index) => {
  var natType = await getNatType(socket, sourceIp, stunHost, stunPort);

  if (!!natType) {
    // If a network error occurred then try running the test again
    if (natType === CHANGE_ADDR_ERR || natType === BLOCKED) {
      return await getIpInfo({ stunHost }, index);
    }
    if (settings.includes(LOGS_ACTIVE))
      console.log(`Test #${index} - NAT TYPE: ${natType}`);
    return natType;
  }
  return ERROR;
};

const genTransactionId = () => {
  // Generates a numeric transaction ID
  return cryptoRandomString({ length: 32, type: "numeric" });
};

const handleStunTestResponse = (address, port, message) => {
  var responseVal = {
    Resp: false,
    ExternalIP: null,
    ExternalPort: null,
    SourceIP: null,
    SourcePort: null,
    ChangedIP: null,
    ChangedPort: null,
  };

  buf = Buffer.from(message);
  msgType = buf.slice(0, 2);

  // Check the response message type
  bindRespMsg = bytesValToMsgType(msgType) == "BindResponseMsg";

  // Check that the transaction IDs match, 0xc2 value is removed as it is
  // an annoying UTF-8 encode byte that messes up the entire comparison
  transIdMatch = transactionIds.find((transId) =>
    transId.includes(
      Buffer.from(message, "binary")
        .slice(4, 30)
        .toString("hex")
        .replace(/c2/g, "")
        .slice(4, 10)
    )
  );

  if (bindRespMsg && !!transIdMatch) {
    transactionIds.slice(transactionIds.length);
    // This is where the fun begins...
    responseVal[RESP] = true;
    msgLen = hexValToInt(`${buf.slice(2, 4).toString("hex")}`);

    var lengthRemaining = msgLen;
    var base = 20;

    while (lengthRemaining > 0) {
      var attrType = bytesToStr(buf.slice(base, base + 2));
      var attrLen = hexValToInt(
        `${bytesToStr(buf.slice(base + 2, base + 4)).replace(/^0+/, "")}`
      );

      // Fetch port and ipAddr value from buffer
      port = hexValToInt(`${bytesToStr(buf.slice(base + 6, base + 8))}`);
      octA = hexValToInt(`${bytesToStr(buf.slice(base + 8, base + 9))}`);
      octB = hexValToInt(`${bytesToStr(buf.slice(base + 9, base + 10))}`);
      octC = hexValToInt(`${bytesToStr(buf.slice(base + 10, base + 11))}`);
      octD = hexValToInt(`${bytesToStr(buf.slice(base + 11, base + 12))}`);
      const ipAddr = [octA, octB, octC, octD].join(".");

      switch (attrType) {
        case stunAttributes.MappedAddress:
          responseVal[EXT_IP] = ipAddr;
          responseVal[EXT_PORT] = port;
        case stunAttributes.SourceAddress:
          responseVal[SRC_IP] = ipAddr;
          responseVal[SRC_PORT] = port;
        case stunAttributes.ChangedAddress:
          responseVal[CHANGED_IP] = ipAddr;
          responseVal[CHANGED_PORT] = port;
        default:
          break;
      }

      base = base + 4 + attrLen;
      lengthRemaining = lengthRemaining - (4 + attrLen);
    }
  }

  return responseVal;
};

const stunTest = (socket, host, port, sendData = "") => {
  var messageReceived = false;
  var bgOp
  var onMessage
  return new Promise((resolve) => {
    const sendMessage = (counter = 0, recursiveSendData) => {
      var dataToSend = recursiveSendData ? recursiveSendData : sendData;
      var strLen = pad(dataToSend.length / 2, 4);
      // Generate a transaction ID and push it to list
      var transactionId = genTransactionId();
      transactionIds.push(transactionId);

      // Generate hex buffer composed of msg, length, transaction ID, and data to send
      var prxData = convertToHexBuffer(`${BindRequestMsg}${strLen}`);
      var transId = convertToHexBuffer(transactionId).slice(0, 16);
      var sndData = convertToHexBuffer(dataToSend);
      var finalData = Buffer.concat([prxData, transId, sndData]);

      socket.send(
        finalData,
        0,
        finalData.length,
        port,
        host,
        (err, nrOfBytesSent) => {
          if (settings.includes(LOGS_ACTIVE))
            console.log("UDP message sent to " + host + ":" + port);

          // Attempt to send messages 3 times otherwise resolve as failure
          bgOp = setTimeout(() => {
            if (!messageReceived) {
              if (counter >= 3) {
                resolve({ Resp: false });
                return;
              }

              sendMessage(counter + 1, dataToSend);
            }
          }, 5000);
          // Add timeout obj to array to clear,
          //   if main process completes before timeouts expire
          backgroundOps.push(bgOp);
        }
      );
    };

    try {
      onMessage = (message, remote) => {
        messageReceived = true;
        const response = handleStunTestResponse(
          remote.address,
          remote.port,
          message
        );

        resolve(response);
      }

      // Upon receiving message, handle it as STUN response
      socket.once("message", onMessage);
      sendMessage();
    } catch (error) {
      if (settings.includes(LOGS_ACTIVE)) console.log(error);
      resolve({ Resp: false });
    }
  }).finally(() => {
    // remove listener if one was added
    if (onMessage) {
      socket.off("message", onMessage);
    }
    // remove any pending tasks
    clearTimeout(bgOp);
  });
};

const getNatType = async (socket, sourceIp, stunHost, stunPort) => {
  var type;
  var stunResult;
  var response = false;

  if (stunHost) {
    stunResult = await stunTest(socket, stunHost, stunPort);
    response = stunResult[RESP];
  }
  if (!response) {
    return BLOCKED;
  }

  var exIP = stunResult[EXT_IP];
  var exPort = stunResult[EXT_PORT];
  var changedIP = stunResult[CHANGED_IP];
  var changedPort = stunResult[CHANGED_PORT];

  var msgAttrLen = "0004";

  if (stunResult[EXT_IP] == sourceIp) {
    var changeRequest = `${stunAttributes.ChangeRequest}${msgAttrLen}00000006`;
    var newStunResult = await stunTest(
      socket,
      stunHost,
      stunPort,
      changeRequest
    );

    if (newStunResult[RESP]) {
      type = OPEN_INTERNET;
    } else {
      type = SYMMETRIC_UDP_FIREWALL;
    }
  } else {
    var changeRequest = `${stunAttributes.ChangeRequest}${msgAttrLen}00000006`;
    var secondStunResult = await stunTest(
      socket,
      stunHost,
      stunPort,
      changeRequest
    );

    if (secondStunResult[RESP]) {
      type = FULL_CONE;
    } else {
      var secondStunResult = await stunTest(socket, changedIP, changedPort);

      if (!secondStunResult[RESP]) {
        type = CHANGE_ADDR_ERR;
      } else {
        if (
          exIP == secondStunResult[EXT_IP] &&
          exPort == secondStunResult[EXT_PORT]
        ) {
          var changePortRequest = `${stunAttributes.ChangeRequest}${msgAttrLen}00000002`;
          var thirdStunResult = await stunTest(
            socket,
            changedIP,
            stunPort,
            changePortRequest
          );
          if (thirdStunResult[RESP]) {
            type = RESTRICTED_NAT;
          } else {
            type = RESTRICTED_PORT_NAT;
          }
        } else {
          type = SYMMETRIC_NAT;
        }
      }
    }
  }

  return type;
};

/* 
   ##########################
   Socket Setup & Main Method
   ##########################
*/

var socket = dgram.createSocket({
  type: "udp4",
  reuseAddr: true,
  recvBufferSize: 2048,
});

const getDeterminedNatType = async (sampleCount, stunHost) => {
  socket.setMaxListeners(sampleCountEventListenerMultiplier * sampleCount);
  socket.bind(sourcePort, sourceIp);

  const resultsList = [];
  // Take 20 samples and find mode value (to determine most probable NAT type)
  for (var i = 0; i < sampleCount; i++) {
    const result = await getIpInfo({ stunHost }, i + 1);
    resultsList.push(result);
  }

  socket.close();
  // Clear timeout operations on socket.messages
  backgroundOps.map((op) => clearTimeout(op));
  const determinedNatType = getModeFromArray(resultsList);
  if (settings.includes(LOGS_ACTIVE)) {
    console.log("\nDetermined NAT Type: ", determinedNatType);
    console.log(
      `A mode value is selected using a ${sampleCount} test samples as failed responses via UDP can cause inaccurate results.`
    );
  }
  return determinedNatType;
};

module.exports = async ({
  logsEnabled = true,
  sampleCount = defaultSampleCount,
  stunHost = defaultStunHost,
}) => {
  if (logsEnabled) settings.push(LOGS_ACTIVE);
  return await getDeterminedNatType(sampleCount, stunHost);
};
