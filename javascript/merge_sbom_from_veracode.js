const axios = require('axios');
import { calculateVeracodeAuthHeader } from './veracode_hmac.js';
let application_quid;
let GET_METHOD = 'get';
const application_url = 'https://api.veracode.com/appsec/v1/applications?page=0&size=500';
const sbom_url = `https://api.veracode.com/srcclr/sbom/v1/targets/${application_quid}/cyclonedx?type=application`;

async function get_applications_guids() {
  let applications_config = {
    method: GET_METHOD,
    maxBodyLength: Infinity,
    url: application_url,
    headers: {
      Authorization:calculateVeracodeAuthHeader(GET_METHOD, application_url)
    }
  };
  try {
    const response = await axios.request(applications_config);
    return response._embedded.applications;
  } catch (error) {
    console.error('Error fetching applications:', error);
    throw error;
  }
}

async function get_application_sboms(get_applications_guids) {
  let sboms = [];
  const sbom_config = {
    method: GET_METHOD,
    maxBodyLength: Infinity,
    url: sbom_url,
    headers: {
      Authorization:calculateVeracodeAuthHeader(GET_METHOD, sbom_url)
    }
  };
  for (const guid of applications_guids) {
    application_quid = guid
    try {
      const response = await axios.request(sbom_config);
      sboms.push(response.data);
    } catch (error) {
      console.error(`Error fetching SBOM for application ${guid}:`, error);
    }
  }
  return sboms;
}

