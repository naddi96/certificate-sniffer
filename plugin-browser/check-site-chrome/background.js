"use strict";
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
  console.log(details)
  
  if (!details.url.startsWith("http://127.0.0.1")){
    let visualizza_pagina= await fetchAsync("http://127.0.0.1/is_domain_ok?domain="+details.url)

    if (!visualizza_pagina){
      chrome.tabs.update({url: "http://127.0.0.1/static/block.html"});
    }
}
//check se il sito details.url è compromesso e nel caso caricare la paggina di warning con
//il comando qui sotto
}

/*
Listen for all onHeadersReceived events.
*/
chrome.webRequest.onHeadersReceived.addListener(logRootCert,
  {urls: ["<all_urls>"]},
  ["blocking"]
);
