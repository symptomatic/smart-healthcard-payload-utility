import { Meteor } from 'meteor/meteor';
import { LinksCollection } from '/imports/api/links';
import { get, has, findIndex } from 'lodash';
import moment from 'moment';


import keychain from '../certs/jwks.json';
let publicKey = get(keychain, 'keys[0]');

import privateKeychain from '../certs/private.jwks.json';
// let signingKey = get(privateKeychain, 'keys[0]');



import fs from 'fs';
import jwt from 'jsonwebtoken';
import jwkToPem from 'jwk-to-pem';
import zlib from 'zlib';
import atob from 'atob';
import btoa from 'btoa';
import pako from 'pako';
import got from 'got';
import jose, { JWK, JWS } from 'node-jose';
import { base64, base64url } from "rfc4648";
import jws from 'jws';
import InflateAuto from 'inflate-auto';


let privatePem
try {
  // assumes that we're running from the .meteor/local/build/* folder
  privatePem = fs.readFileSync('../../../../../certs/ec_private.pem', 'utf8')
  console.log(privatePem)
} catch (err) {
  console.error(err)
}


let signingKey = get(privateKeychain, 'keys[0]');



function zeroPad(num, places){
  return String(num).padStart(places, '0');
}
export function numericMode(inputString){
  let resultArray = [];

  let inputArray = Array.from(inputString);

  inputArray.forEach(function(character, index){
      resultArray.push(zeroPad(inputString.charCodeAt(index) - 45, 2));
  })    

  // convert the array to a comma separated string, and then remove commas
  let result = resultArray.toString().replace(/,/g, "");

  // console.log("numericMode().result", result);
  return result;
}



Meteor.methods({
  async signHealthCard(recordToSign){
    console.log('================SIGNING HEALTHCARD=============================')
    console.log('');


    console.log('');
    console.log('---------------Verified Credential------------------------')        
    console.log('');
    recordToSign.nbf = moment().add(1, "minutes").unix();
    console.log(recordToSign);

    console.log('');
    console.log('---------------FHIR Bundle--------------------------------')        
    console.log('');    
    console.log(get(recordToSign, 'vc.credentialSubject.fhirBundle'));

    console.log('');
    console.log('---------------Signing Key (PEM)--------------------------')        
    console.log('');

    // let privatePem = get(Meteor, 'settings.private.smart.healthcards.privatePem');
    // let privatePem = Assets.getText('certs/ec_private.pem');
    
    console.log(signingKey);
    console.log('');

    console.log('');
    console.log('-----------Public Key (.well-known/jwks.json)-------------')        
    console.log('');

    console.log(publicKey);
    console.log('');

    console.log('');
    console.log('---------------Stringified Payload------------------------')
    console.log('');

    let vcPayloadString = JSON.stringify(recordToSign);
    let vcPayloadString_trimmed = vcPayloadString.trim();
    console.log(vcPayloadString_trimmed);

    // console.log('');
    // console.log('---------------Stringified Payload (btoa)---------------------')
    // console.log('');

    // let vcPayloadString_btoa = btoa(vcPayloadString_trimmed);
    // console.log(vcPayloadString_btoa);


    console.log('');
    console.log('-------------Raw Deflated Payload (Buffer)----------------')
    console.log('');

    let deflatedPayload = zlib.deflateRawSync(vcPayloadString_trimmed);
    console.log(deflatedPayload);

    console.log('');
    console.log('---------------Stringified Payload (btoa)---------------------')
    console.log('');

    let deflatedPayload_btoa = btoa(deflatedPayload);
    console.log(deflatedPayload_btoa);
    
    // let json_web_signature = await jose.JWS
    //   .createSign({ format: 'compact', fields: { zip: 'DEF' }}, signingKey)
    //   .update(deflatedPayload)
    //   .final()
    //   .then(function(result){ 
    //     return result;
    //   });

    let json_web_signature = jws.sign({
      // header: { alg: 'ES256', zip: 'DEF', kid: get(keychain, 'keys[0].kid')},
      header: { alg: 'ES256', zip: 'DEF', kid: get(keychain, 'keys[0].kid')},
      secret: privatePem,
      payload: deflatedPayload_btoa,
      encoding: 'base64'
    });

    console.log('');
    console.log('------------JSON Web Signature (JWS)----------------------')
    console.log('');

    console.log(json_web_signature)     

    Meteor.call('verifyHealthCard', json_web_signature);

    console.log('');
    console.log('------------Smart Health Card----------------------------')
    console.log('');

    let shcNumericString = "shc:/" + numericMode(json_web_signature);
    console.log(shcNumericString)
    console.log('==============================================================================')

    return shcNumericString;
},
async verifyHealthCard(json_web_signature){
    console.log('');
    console.log('================VERIFYING SIGNATURE=======================')
    console.log('');

    console.log(json_web_signature)

    console.log('')     
    console.log('------------Decoded Signature-----------------------------')     
    console.log('')

    // // quality control check
    // // can disable later
    var decoded = jws.decode(json_web_signature);
    console.log(decoded);

    console.log('')
    console.log('-------------Is Verified----------------------------------')
    console.log('')

    // let isVerified = jws.verify(json_web_signature, 'ES256', privatePem);
    let isVerified = jws.verify(json_web_signature, 'ES256', jwkToPem(publicKey));
    console.log(isVerified ? "YES" : "NO")   

    console.log('')
    console.log('------------JWS Parts-------------------------------------')
    console.log('')


    const parts = json_web_signature.split('.');
    console.log(parts)

    console.log('')
    console.log('------------JWS Payload-----------------------------------')
    console.log('')

    const rawPayload = parts[1].trim();
    console.log(rawPayload);

    console.log('')
    console.log('------------Payload Buffer--------------------------------')    
    console.log('')

    
    let buffer_from_payload = Buffer.from(rawPayload);
    console.log(buffer_from_payload);



    console.log('')
    console.log('------------Payload Buffer (from base64)------------------')    
    console.log('')

    
    let buffer_from_base64_payload = Buffer.from(rawPayload, 'base64');
    console.log(buffer_from_base64_payload);


    console.log('')
    console.log('------------Payload Buffer (atob)----------------------------')    
    console.log('')

    
    let buffer_from_atob_payload = Buffer.from(atob(rawPayload));
    console.log(buffer_from_atob_payload);



    console.log('')
    console.log('------------Payload Buffer (from base64, atob)------------------')    
    console.log('')

    
    let buffer_from_atob_base64_payload = Buffer.from(atob(rawPayload), 'base64');
    console.log(buffer_from_atob_base64_payload);



    console.log('')
    console.log('------------Payload Buffer (btoa)----------------------------')    
    console.log('')

    
    let buffer_from_btoa_payload = Buffer.from(btoa(rawPayload));
    console.log(buffer_from_btoa_payload);



    console.log('')
    console.log('------------Payload Buffer (from base64, btoa)------------------')    
    console.log('')

    
    let buffer_from_btoa_base64_payload = Buffer.from(btoa(rawPayload), 'base64');
    console.log(buffer_from_btoa_base64_payload);





    console.log('')
    console.log('------------Decompressed Payload--------------------------')
    console.log('')

        
    const decompressed = zlib.inflateRawSync(buffer_from_base64_payload);    
    const decompressed_string = decompressed.toString('utf8')      
    console.log(decompressed_string); 

    return decompressed_string;
},
async decodeHealthCard(token){
    console.log('================DECODE HEALTHCARD==========================')
    
    console.log(json_web_signature)

    console.log('')
    console.log('------------JWS Payload-----------------------------------')
    console.log('')

    const parts = json_web_signature.split('.');
    const rawPayload = parts[1].trim();
    console.log(rawPayload)

    console.log('')
    // console.log('------------Payload Buffer (atob, base64)-----------------')
    console.log('------------Payload Buffer (atob)-----------------')
    console.log('')

    // per Matt Printz
    // let buffer_from_base64_payload_atob = Buffer.from(rawPayload_atob);
    let buffer_from_base64_payload_atob = Buffer.from(rawPayload_atob, 'base64');
    console.log(buffer_from_base64_payload_atob);

    console.log('')
    console.log('------------Decompressed Payload--------------------------')
    console.log('')
    
    const decompressed = zlib.inflateRawSync(buffer_from_base64_payload_atob);    
    // const decompressed = InflateAuto.inflateAutoSync(buffer_from_base64_payload_atob);    
    const decompressed_string = decompressed.toString('utf8')      
    console.log(decompressed_string); 

    return decompressed_string;
  }
})