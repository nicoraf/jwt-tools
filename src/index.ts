import fs from "fs";
import { exit } from "process";
import { JwtInfo, generateJwtWithData, verifyJwt } from "./jwtUtils"

const args: Array<string> = process.argv.slice(2);

if (args.length < 1 || args.length > 2) {
	console.info('usage: node start [--validate] file');
	console.info('Arguments:');
	console.info('\t-v\t\tvalidate the JWT');
	exit();
}

let filePath: string = '';
let generate: boolean = true;

if (args.length === 2){
	if (args[0] === '--validate') {
		generate = false;
		filePath = args[1];
	}
	else if (args[1] === '--validate') {
		generate = false;
		filePath = args[0];
	}
	else {
		console.error('Invalid args');
		exit();
	}
}
else {
	filePath = args[0];
}

if (generate) {
	generateJwt(filePath);
}
else {
	validateJwt(filePath);
}

function validateJwt(filePath: string)
{
	let data: string | null = null;

	try {
		data = fs.readFileSync(filePath, { encoding: 'utf8', flag: 'r' });
	} catch (err) {
		console.error(`Could not load file ${filePath}`);
		console.error(err);
		exit();
	}

	const splittedData: Array<string> = data.split('.');
	if (splittedData.length != 3) {
		console.error(`Invalid data inside file ${filePath}`);
		exit();
	}

	const jwtInfo: JwtInfo = new JwtInfo(splittedData[0], splittedData[1], splittedData[2]);
	const valid: boolean = verifyJwt(jwtInfo);

	if (valid) {
		console.info(`File ${filePath} contains a valid JWT`);
	}
	else {
		console.info(`File ${filePath} contains an invalid JWT`);
	}
}

function generateJwt(filePath: string)
{
	let data: string | null = null;

	try {
		data = fs.readFileSync(filePath, { encoding: 'utf8', flag: 'r' });
	} catch (err) {
		console.error(`Could not load file ${filePath}`);
		console.error(err);
		exit();
	}
	
	let jwtInfo: JwtInfo | null = null;
	
	try {
		jwtInfo = generateJwtWithData(data);
	} catch (err) {
		console.error('Could not generate JWT');
		console.error(err);
		exit();
	}
	
	console.log(`${jwtInfo.header}.${jwtInfo.payload}.${jwtInfo.hmac}`);
}
