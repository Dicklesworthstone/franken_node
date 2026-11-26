const cluster = require('cluster');
const nodeCluster = require('node:cluster');
console.log('initial-same:' + (cluster.settings === nodeCluster.settings));
cluster.setupPrimary({ exec: 'shared_singleton.js', silent: true });
console.log('updated-same:' + (cluster.settings === nodeCluster.settings));
console.log('visible-exec:' + nodeCluster.settings.exec.endsWith('shared_singleton.js'));
console.log('visible-silent:' + nodeCluster.settings.silent);
