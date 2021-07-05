"use strict";

var rootCertStats = {};

/*
On an onHeadersReceived event, if there was a successful TLS connection
established, fetch the root cert and look at its subject.

If we haven't seen this subject before, add it. If we have, increment its stats.
*/

async function fetchAsync (url) {
  let response = await fetch(url);
  let data = await response.json();
  return data;
}

async function logRootCert(details) {
  try {
    let securityInfo = await browser.webRequest.getSecurityInfo(
      details.requestId,
      {"certificateChain": true}
    );
  if (! details.url.startsWith("http://127.0.0.1")){
    if (securityInfo.state === "secure" || securityInfo.state === "weak"){
        console.log(securityInfo.certificates)
        let fingerprints=""
        for (let i=0;i<securityInfo.certificates.length;i++){
          if (i != securityInfo.certificates.length-1){
            fingerprints=fingerprints+securityInfo.certificates[i].fingerprint.sha256+","
          }else{
            fingerprints=fingerprints+securityInfo.certificates[i].fingerprint.sha256
          }
        }
        let visualizza_pagina= await fetchAsync("http://127.0.0.1/is_list_fingerprint_ok?fingerprint="+fingerprints)

        if (!visualizza_pagina){
          browser.tabs.update({url: "http://127.0.0.1/static/block.html"});
        }

    }}}
  catch(error) {
    console.error(error);
  }
}

/*
Listen for all onHeadersReceived events.
*/
browser.webRequest.onHeadersReceived.addListener(logRootCert,
  {urls: ["<all_urls>"]},
  ["blocking"]
);
