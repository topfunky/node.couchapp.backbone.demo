if ((typeof app) === 'undefined') {
  var app = {};
}

$.extend(true, app, {
  controllers: {

    DaysController: Backbone.Controller.extend({

      // See also some routes defined in initialize().
      routes: {
        '':      'showToday',
        'today': 'showToday'
      },

      initialize: function () {
        this.view = new app.views.AppView();
        this.route(/^(\d{4}-\d{2}-\d{2})$/, 'showDate', this.showDate);
      },

      showToday: function () {
        console.log('showToday');
        app.models.activeDay.resetToToday();
        this.view.render();
        app.collections.events.fetch();
      },

      showDate: function (dateString) {
        console.log('showDate');
        this.view.render();
        app.models.activeDay.setFromDateString(dateString);
      }

    }),

    UncompletedController: Backbone.Controller.extend({

      routes: {
        'uncompleted': 'index'
      },

      initialize: function () {
       this.view = new app.views.UncompletedView();
      },

      index: function () {
        console.log('Showing uncompleted items.');
        this.view.render();
        app.collections.uncompletedEvents.fetch();
      }

    })

  }
});
