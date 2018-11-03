module.exports = function(config) {
    config.set({
        frameworks: ['jasmine', 'karma-typescript'],
        files: [
            {
                pattern: 'src/**/*.ts'
            },
            {
                pattern: 'test/**/*.ts'
            }
        ],
        preprocessors: {
            'src/**/*.ts': ['karma-typescript', 'coverage'],
            'test/**/*.ts': ['karma-typescript']
        },
        reporters: ['progress', 'karma-typescript', 'coverage'],
        browsers: ['ChromeHeadless', 'FirefoxHeadless'],
        coverageReporter: {
            reporters: [{type: 'text-summary'}, {type: 'lcovonly'}]
        }
    });
};
