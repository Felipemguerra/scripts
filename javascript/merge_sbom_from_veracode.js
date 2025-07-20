const axios = require('axios');
const veracode_hmac = require('./veracode_hmac.js');
let config = {
  method: 'get',
  maxBodyLength: Infinity,
  url: 'https://api.veracode.com/appsec/v1/applications?page=1',
  headers: { }
};





axios.request(config)
.then((response) => {
  console.log(JSON.stringify(response.data));
})
.catch((error) => {
  console.log(error);
});
