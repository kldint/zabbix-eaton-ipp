#!/usr/bin/env node

const axios = require('axios');

/**
 * variables load:
 *   var command
 *   var ups
 *   var url
 *   var username
 *   var passwd
 */

var command = process.argv[2]
var ups = process.argv[3]

var url = '127.0.0.1'
var username = 'monitor'
var passwd = 'TO REPLACE'


/**
  * @module SHA1
  */

var SHA1 =
{
  rotate_left: function (n, s) {
    var t4 = (n << s) | (n >>> (32 - s));
    return t4;
  },

  lsb_hex: function (val) {
    var str = "";
    var i;
    var vh;
    var vl;

    for (i = 0; i <= 6; i += 2) {
      vh = (val >>> (i * 4 + 4)) & 0x0f;
      vl = (val >>> (i * 4)) & 0x0f;
      str += vh.toString(16) + vl.toString(16);
    }
    return str;
  },

  cvt_hex: function (val) {
    var str = "";
    var i;
    var v;

    for (i = 7; i >= 0; i--) {
      v = (val >>> (i * 4)) & 0x0f;
      str += v.toString(16);
    }
    return str;
  },

  encode: function (msg) {
    var blockstart;
    var i, j;
    var W = new Array(80);
    var H0 = 0x67452301;
    var H1 = 0xEFCDAB89;
    var H2 = 0x98BADCFE;
    var H3 = 0x10325476;
    var H4 = 0xC3D2E1F0;
    var A, B, C, D, E;
    var temp;

    var msg_len = msg.length;

    var word_array = new Array();
    for (i = 0; i < msg_len - 3; i += 4) {
      j = msg.charCodeAt(i) << 24 | msg.charCodeAt(i + 1) << 16 | msg.charCodeAt(i + 2) << 8 | msg.charCodeAt(i + 3);
      word_array.push(j);
    }

    switch (msg_len % 4) {
      case 0: i = 0x080000000; break;
      case 1: i = msg.charCodeAt(msg_len - 1) << 24 | 0x0800000; break;
      case 2: i = msg.charCodeAt(msg_len - 2) << 24 | msg.charCodeAt(msg_len - 1) << 16 | 0x08000; break;
      case 3: i = msg.charCodeAt(msg_len - 3) << 24 | msg.charCodeAt(msg_len - 2) << 16 | msg.charCodeAt(msg_len - 1) << 8 | 0x80; break;
    }

    word_array.push(i);
    while ((word_array.length % 16) != 14) word_array.push(0);

    word_array.push(msg_len >>> 29);
    word_array.push((msg_len << 3) & 0x0ffffffff);

    for (blockstart = 0; blockstart < word_array.length; blockstart += 16) {
      for (i = 0; i < 16; i++) W[i] = word_array[blockstart + i];
      for (i = 16; i <= 79; i++) W[i] = SHA1.rotate_left(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);

      A = H0; B = H1; C = H2; D = H3; E = H4;

      for (i = 0; i <= 19; i++) {
        temp = (SHA1.rotate_left(A, 5) + ((B & C) | (~B & D)) + E + W[i] + 0x5A827999) & 0x0ffffffff;
        E = D; D = C; C = SHA1.rotate_left(B, 30); B = A; A = temp;
      }

      for (i = 20; i <= 39; i++) {
        temp = (SHA1.rotate_left(A, 5) + (B ^ C ^ D) + E + W[i] + 0x6ED9EBA1) & 0x0ffffffff;
        E = D; D = C; C = SHA1.rotate_left(B, 30); B = A; A = temp;
      }

      for (i = 40; i <= 59; i++) {
        temp = (SHA1.rotate_left(A, 5) + ((B & C) | (B & D) | (C & D)) + E + W[i] + 0x8F1BBCDC) & 0x0ffffffff;
        E = D; D = C; C = SHA1.rotate_left(B, 30); B = A; A = temp;
      }

      for (i = 60; i <= 79; i++) {
        temp = (SHA1.rotate_left(A, 5) + (B ^ C ^ D) + E + W[i] + 0xCA62C1D6) & 0x0ffffffff;
        E = D; D = C; C = SHA1.rotate_left(B, 30); B = A; A = temp;
      }

      H0 = (H0 + A) & 0x0ffffffff;
      H1 = (H1 + B) & 0x0ffffffff;
      H2 = (H2 + C) & 0x0ffffffff;
      H3 = (H3 + D) & 0x0ffffffff;
      H4 = (H4 + E) & 0x0ffffffff;
    }
    var temp = SHA1.cvt_hex(H0) + SHA1.cvt_hex(H1) + SHA1.cvt_hex(H2) + SHA1.cvt_hex(H3) + SHA1.cvt_hex(H4);
    return temp.toLowerCase();
  }
};


/**
  * @module HMAC
  */

var HMAC =
{
  encode: function (key, data) {
    function hexToBin(hStr) {
      var bStr = "";
      for (i = 0; i < hStr.length; i += 2)
        bStr += String.fromCharCode((parseInt(hStr.charAt(i), 16) << 4) + parseInt(hStr.charAt(i + 1), 16));
      return bStr;
    }

    var hashLength = 64;
    if (key.length > hashLength) key = hexToBin(SHA1.encode(key));
    if (key.length < hashLength) key += (new Array(hashLength - key.length + 1)).join("\0");

    var i = 0;
    var ipad = "";
    var opad = "";
    while (i < key.length) {
      opad += String.fromCharCode(key.charCodeAt(i) ^ 0x5C);
      ipad += String.fromCharCode(key.charCodeAt(i) ^ 0x36);
      i++;
    }
    return SHA1.encode(opad + hexToBin(SHA1.encode(ipad + data)));
  }
};


/**
  * @function encodePassword Encode a password.
  * @param {string} passwd Password in readable form.
  * @param {string} challenge Challenge for HMAC authentication.
  * @returns {string} Hashed password.
  */

function encodePassword(passwd, challenge) {
  var res = HMAC.encode(SHA1.encode(passwd), challenge);
  return res;
};

/**
  * @function Request Make an axios HTTP request
  */

async function request({ method, endpoint, params = {}, data = null, cookies = null }) {
  const options = {
    method,
    url: endpoint,
    timeout: 5000,
    validateStatus: null, // handle statusCodes ourselves
    headers: {
      Cookie: cookies,
    },
    params,
  };

  if (data !== null) options.data = data;

  const response = await axios.request(options);

  if (response.status < 200 || response.status >= 300) {
    throw response.data;
  }
  return response;
}

/**
  * @function GetChallenge send a challenge request to IPM.
  * @returns {string} challenge.
  */

async function GetChallenge() {
  data = await request({
    method: 'POST',
    endpoint: "http://" + url + ":4679/server/user_srv.js?action=queryLoginChallenge",
  }).then(response => {
    return response.data.challenge;
  })
  return data;
}

/**
  * @function GetAuthToken request an auth token.
  * @param {string} username the username to use to connect IPM.
  * @param {string} passwd the password to use to connect IPM.
  * @param {string} challenge Challenge for HMAC authentication.
  * @returns {string} Hashed password.
  */

async function GetAuthToken(username, passwd, challenge) {
  let hash = encodePassword(passwd, challenge);
  data = await request({
    method: 'POST',
    endpoint: "http://" + url + ":4679/server/user_srv.js?action=loginUser",
    data: 'login=' + username + '&password=' + hash
  }).then(response => {
    return response.data.sessionID;
  })
    .catch(error => {
      console.log(error);
    })
  return data;
}

/**
  * @function GetUPSData return the JSON with UPS data.
  * @param {string} username the username to use to connect IPM.
  * @param {string} ups the S/N of the UPS.
  * @param {string} token the token for authentication.
  * @returns {string} data of the UPS.
  */

async function GetUPSData(username, ups, token) {
  data = await request({
    method: 'POST',
    endpoint: "http://" + url + ":4679/server/data_srv.js?action=loadNodeData",
    data: 'nodes=%5B%22' + ups + '%22%5D&sessionID=' + token,
    cookies: 'mc2LastLogin=' + username + ";sessionID=" + token,
  }).then(response => {
    for (const [node, nodedata] of Object.entries(response.data.nodeData)) {
      return nodedata;
    }
  })
    .catch(error => {
      console.log(error);
    })
  return data;
}

/**
  * @function DiscoverJSON return the JSON with a list of UPS.
  * @param {string} username the username to use to connect IPM.
  * @param {string} token the token for authentication.
  * @returns {string} list of the UPS.
  */

async function DiscoverJSON(username, token) {
  data = await request({
    method: 'POST',
    endpoint: "http://" + url + ":4679/server/data_srv.js?action=loadNodeList",
    data: 'filter=%5B%7B%22viewID%22%3A%22powersource%22%2C%22object%22%3A%22System.Tag%22%2C%22op%22%3A%22%3D%3D%22%2C%22value%22%3A%22PWS%22%7D%5D&fieldSet=%5B%22nodeID%22%5D&sessionID=' + token,
    cookies: 'mc2LastLogin=' + username + ";sessionID=" + token,
  }).then(response => {
    return response.data.nodeList.nodeData;
  })
    .catch(error => {
      console.log(error);
    })
  return data;
}

/**
  * @function Logout Logout from IPM.
  * @param {string} username the username to use to connect IPM.
  * @param {string} token the token for authentication.
  * @returns {string} nothing.
  */

async function Logout(username, token) {
  data = await request({
    method: 'POST',
    endpoint: "http://" + url + ":4679/server/user_srv.js?action=logoutUser",
    data: 'sessionID=' + token,
    cookies: 'mc2LastLogin=' + username + ";sessionID=" + token,
  }).then(response => {
    return response;
  })
    .catch(error => {
      console.log(error);
    })
  return data;
}

/**
  * @function GetJSON Get JSON array of the UPS data
  * @returns {string} return the data of the UPS in JSON format.
  */

async function GetJSON() {
  const challenge = await GetChallenge();
  const token = await GetAuthToken(username, passwd, challenge);
  const upsdata = await GetUPSData(username, ups, token);
  const logout = await Logout(username, token);
  console.log(JSON.stringify(upsdata));
  return JSON.stringify(upsdata);
}

/**
  * @function GetDiscoverJSON Get the JSON of all UPS
  * @returns {string} return the list of all UPS.
  */

async function GetDiscoverJSON() {
  const challenge = await GetChallenge();
  const token = await GetAuthToken(username, passwd, challenge);
  const upslist = await DiscoverJSON(username, token);
  let list = [];
  for (var nodename in upslist) {
    const upsdata = await GetUPSData(username, nodename, token)
    let node = {
      '{#UPS_NAME}': upsdata['System.Name'],
      '{#UPS_SN}': nodename
    }
    list.push(node);
  }
  let discovered = {
    data: list,
  }
  const logout = await Logout(username, token);
  console.log(JSON.stringify(discovered));
  return JSON.stringify(discovered);
}

if (command == 'get') {
  return GetJSON();
} else {
  return GetDiscoverJSON();
}
