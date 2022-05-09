const crypto = require('crypto');

module.exports = {
  name: 'signature-verify',
  schema: {
    $id: 'N/A',
    type: 'object',
    properties: {
      apikeys: {
        type: 'array',
      }
    }
  },
  policy: ({ encoding = 'hex', endpoint, headers=[], body, signature, secret, algorithm = 'SHA256' }) => {
    return async (req, res, next) => {
      try {
				let isValid = false;
				if ((headers.length || body.length) && signature && secret) {
					const sig = req.headers[signature]
					let payload = '';
					if(endpoint) payload += (endpoint + "\n")
					if(body) payload += (req.body + "\n")
					headers.forEach((x, i) => {
						payload += req.headers[x];
						if(i < headers.length - 1) payload += "\n"
					})

					const hash = crypto.createHmac(algorithm, secret);
					hash.update(payload);
          if (sig === hash.digest(encoding)) {
            isValid = true;
          }
				}
       
        if (!isValid) {
          res.sendStatus(401);
          return;
        };
      } catch (e) {
        console.error('Error in signature-verify policy:', e.error);
        res.sendStatus(500);
        return;
      }
      next();
    };
  }
};
