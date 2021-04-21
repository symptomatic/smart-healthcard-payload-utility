import React, { useState } from 'react';
import { Meteor } from 'meteor/meteor';


function compactRecord(fhirResource){
  console.log('Compacting resource....', fhirResource)
  let result = Object.assign({}, fhirResource);
  delete result._document;
  delete result._id;
  delete result.id;
  delete result.meta;
  delete result.requester;
  delete result.reporter;
  delete result.vaccineCode.text
  delete result.wasNotGiven;
  delete result.reported;

  return result;
}


export const HelloHealthCard = () => {
  const [counter, setCounter] = useState(0);

  const generateHealthCard = () => {


    let certificateBundle = {
      "iss": "http://localhost:3000",
      "nbf": 10,
      "vc": {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": [
          "VerifiableCredential",
          "https://smarthealth.cards#health-card",
          "https://smarthealth.cards#immunization"
        ],
        "credentialSubject": {
          "fhirVersion": "4.0.1",
          "fhirBundle":{
            "resourceType": "Bundle",
            "type": "collection",
            "entry": []
          }
        }
      }
    }


    let sampleImmunizationRecord = {
      "status" : "completed",
      "wasNotGiven" : false,
      "patient" : {
        "display" : "Candace Salinas",
        "reference" : "Patient/100"
      },
      "id" : "immunization-mmr",
      "encounter" : {
        "reference" : "Encounter/129837645"
      },
      "date" : "2021-03-05",
      "requester" : {
        "display" : "Altick Kelly",
        "reference" : "Practitioner/8"
      },
      "reported" : false,
      "vaccineCode" : {
        "text" : "SARS-COV-2 (COVID-19) vaccine, mRNA, spike protein, LNP, preservative free, 30 mcg/0.3mL dose",
        "coding" : [
          {
            "system" : "CVX",
            "code" : "208"
          }
        ]
      },
      "resourceType" : "Immunization"
    }

    console.log('Sample Immunization Record: ', sampleImmunizationRecord)


    certificateBundle.vc.credentialSubject.fhirBundle.entry.push({
      fullUrl: "Immunization/0",
      resource: compactRecord(sampleImmunizationRecord)
    });

    console.log('Minimized certificate bundle: ', certificateBundle)

    Meteor.call('signHealthCard', certificateBundle, function(error, result){
      if(result){
        alert(result)
      }
    })
  };

  return (
    <div>
      <button onClick={generateHealthCard.bind(this)}>Generate HealthCard</button>      
    </div>
  );
};
