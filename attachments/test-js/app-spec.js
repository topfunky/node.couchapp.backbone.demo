
// Most specs are in itemized files (model-spec.js, util-spec.js).

$(document).ready(function(){

  var db = $.couch.db(Backbone.couchConnector.databaseName);
  db.create();

});

