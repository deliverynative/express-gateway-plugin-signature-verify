module.exports = {
  version: '1.2.4',
  init: (pluginContext) => {
     pluginContext.registerPolicy(require('./policies/signature-verify.policy'))
  },
  policies: ['signature-verify'],
  schema: {
    $id: 'N/A',
  }
}
