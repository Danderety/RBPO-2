const security = require('eslint-plugin-security');
module.exports = [security.configs.recommended, {
  files: ['*.js'],
  languageOptions: {ecmaVersion: 2022, sourceType: 'commonjs'},
}];
