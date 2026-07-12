const events = require('events');
console.log(events.captureRejections === false);
console.log(typeof events.captureRejections);
