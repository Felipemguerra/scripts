import 'axios';
//import { calculateVeracodeAuthHeader } from './veracode_hmac.js';
import { mkdir, writeFile, rm, unlink } from 'node:fs/promises';
import path from 'node:path'
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);
let application_quid;
let folder_name = 'sboms';
let output_file = 'tx-gov.sbom.json'
let GET_METHOD = 'get';
let PARAMS = '?page=0&size=500';
const application_url = `https://api.veracode.com/appsec/v1/applications${PARAMS}`;
const sbom_url = `https://api.veracode.com/srcclr/sbom/v1/targets/${application_quid}/cyclonedx?type=application`;

async function get_application_guids() {
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
async function get_application_sboms(get_application_guids) {
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
async function write_sboms_to_folder(sboms_array, folder_name) {
  try {
    await mkdir(folder_name, { recursive: true });

    const tasks = sboms_array.map((sbom, idx) => {
      const filename = path.join(folder_name, `sbom-${idx + 1}.json`);
      const content = typeof sbom === 'string'
        ? sbom
        : JSON.stringify(sbom, null, 2);
      return writeFile(filename, content, 'utf8');
    });

    await Promise.all(tasks);
    console.log(`Successfully wrote ${sboms_array.length} files to "${folder_name}".`);
  } catch (err) {
    console.error('Error writing files:', err);
  }
}
async function merge_sboms(inputFiles, output_file) {
  const args = ['merge', '--input-files', folder_name+'/*.json', '--output-file', output_file];
  try {
    const { stdout, stderr } = await run('cyclonedx', args);
    console.log('Merged SBOM written to', output_file);
  } catch (err) {
    console.error('Merge failed:', err.stderr ?? err);
  }
}
async function cleanup(folder_name) {
  try {
    await rm(folder_name, { recursive: true, force: true });
    console.log(`Successfully deleted "${folder_name}" and its contents.`);
  } catch (err) {
    console.error('Failed to delete folder:', err);
  }
  try {
    await unlink('cyclonedx');
    console.log('File deleted successfully.');
  } catch (err) {
    console.error('Could not delete file:', err);
  }
}

let application_guid_array = get_application_guids();
let sboms_array = get_application_sboms(application_guid_array);
await write_sboms_to_folder(sboms_array, folder_name);
await merge_sboms(folder_name, output_file);
cleanup(folder_name)
