/*jslint white: false, onevar: true, browser: true, devel: true, undef: true, nomen: true, eqeqeq: true, plusplus: true, bitwise: true, regexp: true, strict: false, newcap: true, immed: true */
/*global _, $, window, Backbone, Mustache */

if ((typeof app) === 'undefined') {
  var app = {};
}

$(document).ready(function () {

  Backbone.couchConnector.databaseName = "time_track";
  Backbone.couchConnector.ddocName = "time_track";
  Backbone.couchConnector.viewName = "by_collection";
  // If set to true, the connector will listen to the changes feed
  // and will provide your models with real time remote updates.
  //Backbone.couchConnector.enableChanges = true;
  $('body').ajaxStart(function () {
    $('.loading').text('Synchronizing...').show();
  });
  $('body').ajaxStop(function () {
    $('.loading').hide();
  });
  $('body').ajaxError(function () {
    $('#loading').text('Lost connection to server.').show();
  });

  var controller = new app.controllers.DaysController();
  var uncompletedController = new app.controllers.UncompletedController();
  Backbone.history.start();

});
