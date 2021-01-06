const dgram = require("dgram");
const binascii = require("binascii");

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

// CONSTANTS
const BLOCKED = "Blocked";
const ERROR = "Error, check logs.";

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

const getIpInfo = ({
  sourceIp = "0.0.0.0",
  sourcePort = 54320,
  stunHost = "None",
  stunPort = 3478,
}) => {
  socket.bind(sourcePort, sourceIp);

  var { natType, nat } = getNatType(
    socket,
    sourceIp,
    sourcePort,
    stunHost,
    stunPort
  );

  //   if (nat) {
  //     externalIp = nat["ExternalIP"];
  //     externalPort = nat["ExternalPort"];
  //     socket.close();
  //     return natType, externalIp, externalPort;
  //   }

  //   socket.close();
  //   return ERROR;
};

const genTransactionId = () => {
  const num = "0123456789";
  let output = "";
  for (let i = 0; i < 32; ++i) {
    output += num.charAt(Math.floor(Math.random() * num.length));
  }
  return output;
};

const handleStunTestResponse = (
  address,
  port,
  message,
  transId,
  responseVal
) => {
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
      .slice(4, 26)
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

      console.log("AttrType: ", attrType);
      console.log("AttrLength: ", attrLen);

      port = hexValToInt(`${bytesToStr(buf.slice(base + 6, base + 8))}`);
      console.log("Port: ", port);

      octA = hexValToInt(`${bytesToStr(buf.slice(base + 8, base + 9))}`);
      octB = hexValToInt(`${bytesToStr(buf.slice(base + 9, base + 10))}`);
      octC = hexValToInt(`${bytesToStr(buf.slice(base + 10, base + 11))}`);
      octD = hexValToInt(`${bytesToStr(buf.slice(base + 11, base + 12))}`);
      const ipAddr = [octA, octB, octC, octD].join(".");
      console.log("IP: ", `${ipAddr}`);

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

      // End of while:
      base = base + 4 + attrLen;
      lengthRemaining = lengthRemaining - (4 + attrLen);
    }
  }
  responseVal;
};

const stunTest = (socket, host, port, sourceIp, sourcePort, sendData = "") => {
  var responseVal = {
    Resp: false,
    ExternalIP: null,
    ExternalPort: null,
    SourceIP: null,
    SourcePort: null,
    ChangedIP: null,
    ChangedPort: null,
  };

  strLen = pad(sendData.length / 2, 4);
  transactionId = genTransactionId();
  strData = `${BindRequestMsg}${strLen}${transactionId}${sendData}`;
  data = binascii.a2b_hex(strData).toUpperCase();

  socket.on("message", function (message, remote) {
    return handleStunTestResponse(
      remote.address,
      remote.port,
      message,
      binascii.hexlify(data).toUpperCase(),
      responseVal
    );
  });

  try {
    socket.send(data, 0, data.length, port, host, (err, nrOfBytesSent) => {
      if (err) return console.log(err);
      console.log("UDP message sent to " + host + ":" + port);
    });
  } catch (error) {
    console.log(error);
    return { Resp: false };
  }

  return responseVal;
};

const getNatType = (socket, sourceIp, sourcePort, stunHost, stunPort) => {
  console.log("Starting test...");

  var stunResult;
  var response = false;

  if (stunHost) {
    stunResult = stunTest(socket, stunHost, stunPort, sourceIp, sourcePort);
    response = stunResult["Resp"];
  }
  if (!response) {
    return BLOCKED, stunResult;
  }

  console.log("Result: %s", stunResult);
  // exIP = stunResult['ExternalIP']
  // exPort = stunResult['ExternalPort']
  // changedIP = stunResult['ChangedIP']
  // changedPort = stunResult['ChangedPort']
  // if stunResult['ExternalIP'] == source_ip:
  //     changeRequest = ''.join([ChangeRequest, '0004', "00000006"])
  //     stunResult = stun_test(s, stun_host, stun_port, source_ip, source_port,
  //                     changeRequest)
  //     if stunResult['Resp']:
  //         typ = OpenInternet
  //     else:
  //         typ = SymmetricUDPFirewall
  // else:
  //     changeRequest = ''.join([ChangeRequest, '0004', "00000006"])
  //     log.debug("Do Test2")
  //     stunResult = stun_test(s, stun_host, stun_port, source_ip, source_port,
  //                     changeRequest)
  //     log.debug("Result: %s", stunResult)
  //     if stunResult['Resp']:
  //         typ = FullCone
  //     else:
  //         log.debug("Do Test1")
  //         stunResult = stun_test(s, changedIP, changedPort, source_ip, source_port)
  //         log.debug("Result: %s", stunResult)
  //         if not stunResult['Resp']:
  //             typ = ChangedAddressError
  //         else:
  //             if exIP == stunResult['ExternalIP'] and exPort == stunResult['ExternalPort']:
  //                 changePortRequest = ''.join([ChangeRequest, '0004',
  //                                             "00000002"])
  //                 log.debug("Do Test3")
  //                 stunResult = stun_test(s, changedIP, port, source_ip, source_port,
  //                                 changePortRequest)
  //                 log.debug("Result: %s", stunResult)
  //                 if stunResult['Resp']:
  //                     typ = RestricNAT
  //                 else:
  //                     typ = RestricPortNAT
  //             else:
  //                 typ = SymmetricNAT

  return { natType: 1, nat: { ExternalIP: 0, ExternalPort: 0 } };
};

getIpInfo({ stunHost: "stun.sipgate.net" });
