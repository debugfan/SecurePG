/**
 * Sample React Native App
 * https://github.com/facebook/react-native
 * @flow
 */

import React, { Component } from 'react';
import {
  Alert,
  Button, 
  TextInput,
  Platform,
  StyleSheet,
  Text,
  View
} from 'react-native';

import { JSEncrypt } from 'jsencrypt';
import { NetworkInfo } from 'react-native-network-info';
var RNFS = require('react-native-fs');
var CryptoJS = require("crypto-js");
var jsrsasign = require("jsrsasign");
var net = require('react-native-tcp');

const instructions = Platform.select({
  ios: 'Press Cmd+R to reload,\n' +
    'Cmd+D or shake for dev menu',
  android: 'Double tap R on your keyboard to reload,\n' +
    'Shake or press menu button for dev menu',
});

function decrypt_key(secret, password, enckey, label) {
  // Decrypt private key using passphrase
  decPKHex = jsrsasign.KEYUTIL.getDecryptedKeyHex(secret, password);
  // Convert to PEM format for JSEncrypt
  decPKPEM = jsrsasign.KJUR.asn1.ASN1Util.getPEMStringFromHex(decPKHex, "RSA PRIVATE KEY");
  
  // Decrypt with the private key...
  var decrypt = new JSEncrypt();
  decrypt.setPrivateKey(decPKPEM);
  var uncrypted = decrypt.decrypt(enckey);
  var dek = CryptoJS.HmacSHA256(label, uncrypted);
  
  return dek;
}

type Props = {};
export default class App extends Component<Props> {
  constructor(props) {
    super(props);
    this.state = {url: "http://192.168.0.100/example.key", ip: "0.0.0.0", port: "9600", server: null, secret: "", password: "123456", started: false};

    this.importFile = this.importFile.bind(this);
    this.removeFile = this.removeFile.bind(this);
    this.startService = this.startService.bind(this);
    this.stopService = this.stopService.bind(this);
  }
   
  importFile() {
    var url = this.state.url;

    if(url == "") {
      Alert.alert('Error', 'No URL specified!');
      return;
    }

    fetch(url)
      .then((response) => response.text())
      .then((body) => {
        var path = RNFS.DocumentDirectoryPath + '/secret.key';
        // write the file
        console.log('Writing file: ', path, body);
        RNFS.writeFile(path, body)
        .then((success) => {
          Alert.alert('Information', 'Import successfully!');
        })
        .catch((err) => {
          console.log(err.message);
        });
      })
      .catch((error) => {
        console.error(error);
      });
  }

  removeFile() {
    // create a path you want to delete
    var path = RNFS.DocumentDirectoryPath + '/secret.key';

    RNFS.unlink(path)
      .then(() => {
        console.log('FILE DELETED');
        Alert.alert('Information', 'Delete successfully!');
      })
      // `unlink` will throw an error, if the item to unlink does not exist
      .catch((err) => {
        console.log(err.message);
      });
  }

  start_agent_server(ip, port, secret, password) {
    console.log('listen on ' + ip + ':' + port);

    var srv = net.createServer(function(socket) {
      
      socket.secureRecv = function(data) {
        if (typeof(socket.sessionKey) == "undefined") {
          var session = JSON.parse(data);
          socket.sessionKey = decrypt_key(secret, password, session.key, session.label);
          payload = CryptoJS.AES.decrypt(session.data, socket.sessionKey, {mode: CryptoJS.mode.ECB});
          return payload.toString(CryptoJS.enc.Latin1);
        } else {
          payload = CryptoJS.AES.decrypt(data, socket.sessionKey, {mode: CryptoJS.mode.ECB});
          return payload.toString(CryptoJS.enc.Latin1);
        }
      }

      socket.secureSend = function(data) {
        var enc_data = CryptoJS.AES.encrypt(data, socket.sessionKey, {mode: CryptoJS.mode.ECB});
        socket.write(enc_data.toString());
      }

      socket.on('data', function(data) {
        var app_data = socket.secureRecv(data);     
        var app_json = JSON.parse(app_data);
        Alert.alert(
          'Decrypt Request',
          'Client: ' + socket.address().address + '\nLabel: ' + app_json.label,
          [
            {text: 'Accept', onPress: () => {
              console.log('Decrypt request accepted.');
              var dek = decrypt_key(secret, password, app_json.key, app_json.label);
              socket.secureSend(dek.toString(CryptoJS.enc.Base64));
            }},
            {text: 'Reject', style: 'cancel', onPress: () => {
              console.log('Cancel Pressed');
              socket.close();
            }}
          ],
          { cancelable: false }
        )
      });
    
      // Add a 'close' event handler to this instance of socket
      socket.on('close', function(data) {
         console.log('Connection closed.');
      });
    }).listen(port, ip);

    this.setState({server: srv});
    this.setState({started: true});
  }

  startService() {
    if(this.state.password == "") {
      Alert.alert('Warning', 'No password set!');
    }

    var password = this.state.password;
    var ip = this.state.ip;
    var port = parseInt(this.state.port);

    var path = RNFS.DocumentDirectoryPath + '/secret.key';
    console.log('secret file path: ', path);

    RNFS.readFile(path, 'utf8')
      .then((contents) => {
        this.start_agent_server(ip, port, contents, password);
      })
      .catch((err) => {
        console.log(err.message, err.code);
      });
  }

  stopService() {
    if(this.state.server != null) {
      this.state.server.close();
    }
    
    this.setState({started: false});
  }

  componentDidMount() {
    NetworkInfo.getIPAddress(aip => {
      console.log('Local IP: ' + aip);
      this.setState({ip: aip});
    });  
  }
  
  render() {
    return (
      <View style={styles.container}>
        <View style={styles.row}>
          <Text>URL: </Text>
          <TextInput
            value={this.state.url}
            onChangeText={(text) => this.setState({url: text})}
          />
        </View>
        <View style={styles.row}>
          <Button
            onPress={this.importFile}
            title="Import"
          />
          <Button
            onPress={this.removeFile}
            title="Remove"
          />
        </View>
        <View style={styles.row}>
          <Text>Password: </Text>
          <TextInput
            secureTextEntry={true}
            value={this.state.password}
            onChangeText={(text) => this.setState({password: text})}
          />
        </View>
        <View style={styles.row}>
          <Text>IP: {this.state.ip}</Text>
        </View>
        <View style={styles.row}>
          <Text>Port: </Text>
          <TextInput
            value={this.state.port}
            onChangeText={(text) => this.setState({port: text})}
          />
        </View>
        <View style={styles.row}>
          <Button
            onPress={this.startService}
            title="startService"
            disabled={this.state.started}
          />
          <Button
            onPress={this.stopService}
            title="stopService"
            disabled={!this.state.started}
          />
        </View>
      </View>
    );
  }
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#F5FCFF',
  },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
  },
});
