export default {
    transform: {
        '^.+\\.js$': 'babel-jest'
    },
    testEnvironment: 'node',
    moduleNameMapper: {
        '^(\\.{1,2}/.*)\\.js$': '$1'
    },
    transformIgnorePatterns: [
        'node_modules/(?!(jose)/)'  // Transform jose module
    ],
    testEnvironmentOptions: {
        customExportConditions: ['node', 'node-addons'] // For jose in Node.js
    },
    setupFiles: ['./test/setup.js']
}; 