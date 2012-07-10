if ((typeof app) === 'undefined') {
  var app = {};
}

$.extend(true, app, {
  keys: {

    setup: function () {
      app.keys.setupForElement('body');
      app.keys.setupForElement('#new_event');
    },

    setupForElement: function (element) {
      $(element).bind('keydown', 'alt+ctrl+n', function () {
        window.location.hash = "#" + app.models.activeDay.nextId();
      })
      $(element).bind('keydown', 'alt+ctrl+p', function () {
        window.location.hash = "#" + app.models.activeDay.previousId();
      })
      $(element).bind('keydown', 'alt+ctrl+t', function () {
        window.location.hash = "#today";
      })
      $(element).bind('keydown', 'alt+ctrl+d', function () {
        window.location.hash = "#uncompleted";
      })
    }

  }
});
