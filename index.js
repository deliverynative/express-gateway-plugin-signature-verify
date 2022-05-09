const policy = require('./policies/signature-verify.policy.js')

const run = async() => {
	const f =  policy.policy({encoding: 'base64', signature: 'test', body: true, secret: 'test'})
	await f()
}

run()