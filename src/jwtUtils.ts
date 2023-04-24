import base64url from "base64url";
import crypto from 'crypto';

const secret = 'a9ddbcaba8c0ac1a0a812dc0c2f08514b23f2db0a68343cb8199ebb38a6d91e4ebfb378e22ad39c2d01d0b4ec9c34aa91056862ddace3fbbd6852ee60c36acbf';
const secret_buffer = Buffer.from(secret, "hex");

class JwtInfo 
{
	constructor(public header:string, public payload:string, public hmac: string) {}
}

function generateJwtHmacWithObjects(header: any, payload: any): JwtInfo
{
	const header_str = JSON.stringify(header);
	const encoded_header = base64url.encode(header_str);

	const payload_str = JSON.stringify(payload);
	const encoded_payload = base64url.encode(payload_str);

	const hmac = generateJwtHmac(encoded_header, encoded_payload);
	return new JwtInfo(encoded_header, encoded_payload, hmac);
}

function generateJwtHmac(encoded_header: string, encoded_payload: string): string
{
	const hmac = crypto.createHmac('sha512', secret_buffer);

	hmac.update(Buffer.from(encoded_header, 'utf-8'));
	hmac.update(Buffer.from('.', 'utf-8'));
	hmac.update(Buffer.from(encoded_payload, 'utf-8'));
	
	const digest: Buffer = hmac.digest();
	return base64url.encode(digest);
}

function generateJwtWithData(data: string): JwtInfo
{
	const header = {
		"typ": "JWT",
		"alg": "HS512"
	};
	
	const iat = Math.floor(new Date().getTime() / 1000);
	const jti_bytes = crypto.randomBytes(32);
	const jti = jti_bytes.toString('hex');
	const date = new Date().toISOString();
	
	const payload = {
		data: data,
		date: date
	};
	
	const jwt_payload = {
		"iat": iat,
		"jti": jti,
		"payload": payload
	};
	 
	return generateJwtHmacWithObjects(header, jwt_payload);
}

// NOTE: this only verifies JWT generated using this tool
function verifyJwt(jwt_info: JwtInfo): boolean
{
	const calc_hmac = generateJwtHmac(jwt_info.header, jwt_info.payload);
	return calc_hmac === jwt_info.hmac;
}

export { JwtInfo, generateJwtWithData, verifyJwt };