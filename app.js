const dgram = require("dgram");
const binascii = require("binascii");
const { start } = require("repl");

// Types for a STUN message
const BindRequestMsg = "0001";
const BindResponseMsg = "0101";
const BindErrorResponseMsg = "0111";
const SharedSecretRequestMsg = "0002";
const SharedSecretResponseMsg = "0102";
const SharedSecretErrorResponseMsg = "0112";

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
  Username: "0006",
  Password: "0007",
  MessageIntegrity: "0008",
  ErrorCode: "0009",
  UnknownAttribute: "000A",
  ReflectedFrom: "000B",
  XorOnly: "0021",
  XorMappedAddress: "8020",
  ServerName: "8022",
  SecondaryAddress: "8050",
};

// NAT Types
const BLOCKED = "Blocked";
const OPEN_INTERNET = "Open Internet";
const FULL_CONE = "Full Cone";
const SYMMETRIC_UDP_FIREWALL = "Symmetric UDP Firewall";
const RESTRICTED_NAT = "Restric NAT";
const RESTRICTED_PORT_NAT = "Restric Port NAT";
const SYMMETRIC_NAT = "Symmetric NAT";

const CHANGE_ADDR_ERR = "Meet an error, when do Test1 on Changed IP and Port";

/* 
   #######################
   Generic/Re-Used Methods
   #######################
*/

const pad = (num, size) => {
  num = num.toString();
  while (num.length < size) num = "0" + num;
  return num;
};

/* 
   #########################
   Main Methods
   #########################
*/

var socket = dgram.createSocket({
  type: "udp4",
  reuseAddr: true,
  recvBufferSize: 2048,
});

const bytesToStr = (bytes) => {
  return `${pad(bytes[0].toString(16), 2)}${
    !!bytes[1] ? pad(bytes[1].toString(16), 2) : ""
  }`;
};

const bytesValToMsgType = (bytes) => {
  return msgTypes[`${bytesToStr(bytes)}`];
};

const hexValToInt = (hex) => {
  return parseInt(Number(`0x${hex}`), 10);
};

const getIpInfo = async ({
  sourceIp = "0.0.0.0",
  sourcePort = 54320,
  stunHost = "None",
  stunPort = 3478,
}) => {
  socket.bind(sourcePort, sourceIp);

  console.log("GetIpInfo1");
  var natType = await getNatType(socket, sourceIp, stunHost, stunPort);
  console.log("GetIpInfo2");

  if (!!natType) {
    console.log("GetIpInfo3");
    socket.close();
    return natType;
  }

  console.log("GetIpInfo4");
  // socket.close();
  // return ERROR;
};

const genTransactionId = () => {
  const num = "0123456789";
  let output = "";
  for (let i = 0; i < 32; ++i) {
    output += num.charAt(Math.floor(Math.random() * num.length));
  }
  return output;
};

const handleStunTestResponse = (address, port, message, transId) => {
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
  console.log("bindRespMsg Response: ", bytesValToMsgType(msgType));

  // Check that the transaction IDs match, c2 A value is removed as it is
  // an annoying UTF-8 encode byte that messes up the entire comparison
  transIdMatch = transId.includes(
    Buffer.from(message, "binary")
      .slice(4, 30)
      .toString("hex")
      .replace(/c2/g, "")
      .slice(4, 10)
  );

  if (bindRespMsg && transIdMatch) {
    // This is where the fun begins...
    responseVal["Resp"] = true;
    msgLen = hexValToInt(`${buf.slice(2, 4).toString("hex")}`);

    var lengthRemaining = msgLen;
    var base = 20;

    while (lengthRemaining > 0) {
      var attrType = bytesToStr(buf.slice(base, base + 2));
      var attrLen = hexValToInt(
        `${bytesToStr(buf.slice(base + 2, base + 4)).replace(/^0+/, "")}`
      );

      port = hexValToInt(`${bytesToStr(buf.slice(base + 6, base + 8))}`);

      octA = hexValToInt(`${bytesToStr(buf.slice(base + 8, base + 9))}`);
      octB = hexValToInt(`${bytesToStr(buf.slice(base + 9, base + 10))}`);
      octC = hexValToInt(`${bytesToStr(buf.slice(base + 10, base + 11))}`);
      octD = hexValToInt(`${bytesToStr(buf.slice(base + 11, base + 12))}`);
      const ipAddr = [octA, octB, octC, octD].join(".");

      switch (attrType) {
        case stunAttributes.MappedAddress:
          responseVal["ExternalIP"] = `${ipAddr}`;
          responseVal["ExternalPort"] = port;
        case stunAttributes.SourceAddress:
          responseVal["SourceIP"] = `${ipAddr}`;
          responseVal["SourcePort"] = port;
        case stunAttributes.ChangedAddress:
          responseVal["ChangedIP"] = `${ipAddr}`;
          responseVal["ChangedPort"] = port;
      }

      base = base + 4 + attrLen;
      lengthRemaining = lengthRemaining - (4 + attrLen);
    }
  }
  return responseVal;
};

convertToHexBuffer = (text) => {
  return Buffer.from(binascii.a2b_hex(text).toUpperCase());
};

const stunTest = async (socket, host, port, sendData = "") => {
  var messageReceived = false;
  var strLen = pad(sendData.length / 2, 4);
  var transactionId = genTransactionId();

  var prxData = convertToHexBuffer(`${BindRequestMsg}${strLen}`);
  var transId = convertToHexBuffer(transactionId).slice(0, 16);
  var sndData = convertToHexBuffer(sendData);

  var finalData = Buffer.concat([prxData, transId, sndData]);

  return new Promise((resolve) => {
    sendMessage = () => {
      socket.send(
        finalData,
        0,
        finalData.length,
        port,
        host,
        (err, nrOfBytesSent) => {
          if (err) resolve(console.log(err));
          console.log("UDP message sent to " + host + ":" + port);

          setTimeout(() => {
            if (!messageReceived) {
              sendMessage();
            }
          }, 2000);
        }
      );
    };

    try {
      socket.on("message", (message, remote) => {
        messageReceived = true;
        const response = handleStunTestResponse(
          remote.address,
          remote.port,
          message,
          transactionId
        );
        resolve(response);
      });

      sendMessage();
    } catch (error) {
      console.log(error);
      resolve({ Resp: false });
    }
  });
};

const getNatType = async (socket, sourceIp, stunHost, stunPort) => {
  console.log("Starting Tests...");

  var type;
  var stunResult;
  var response = false;

  if (stunHost) {
    stunResult = await stunTest(socket, stunHost, stunPort);
    response = stunResult["Resp"];
  }
  if (!response) {
    return BLOCKED, stunResult;
  }

  var exIP = stunResult["ExternalIP"];
  var exPort = stunResult["ExternalPort"];
  var changedIP = stunResult["ChangedIP"];
  var changedPort = stunResult["ChangedPort"];

  if (stunResult["ExternalIP"] == sourceIp) {
    var changeRequest = `${stunAttributes.ChangeRequest}000400000006`;
    var newStunResult = await stunTest(
      socket,
      stunHost,
      stunPort,
      changeRequest
    );

    if (newStunResult["Resp"]) {
      type = OPEN_INTERNET;
    } else {
      type = SYMMETRIC_UDP_FIREWALL;
    }
  } else {
    var changeRequest = `${stunAttributes.ChangeRequest}000400000006`;
    console.log("Do Test2");
    var secondStunResult = await stunTest(
      socket,
      stunHost,
      stunPort,
      changeRequest
    );

    console.log("Result: ", secondStunResult);
    if (secondStunResult["Resp"]) {
      type = FULL_CONE;
    } else {
      console.log("Do Test1");
      var secondStunResult = await stunTest(socket, changedIP, changedPort);

      console.log("Result: ", secondStunResult);
      if (!secondStunResult["Resp"]) {
        type = CHANGE_ADDR_ERR;
      } else {
        if (
          exIP == secondStunResult["ExternalIP"] &&
          exPort == secondStunResult["ExternalPort"]
        ) {
          var changePortRequest = `${stunAttributes.ChangeRequest}000400000002`;
          console.log("Do Test3");
          var thirdStunResult = await stunTest(
            socket,
            changedIP,
            stunPort,
            changePortRequest
          );
          console.log("Result: ", thirdStunResult);
          if (thirdStunResult["Resp"]) {
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

getIpInfo({ stunHost: "stun.sipgate.net" });
