// collections
$.extend(true, app, {
  collections: {

    events: new (Backbone.Collection.extend({

      model: app.models.Event,

      viewName: 'byEvent',

      viewOptions: {
        key: app.models.activeDay.get('id')
      },

      url: (new app.models.Event().url),

      initialize: function () {
        _.bindAll(this, 'changeDay');
        app.models.activeDay.bind('change', this.changeDay);
      },

      changeDay: function () {
        this.viewOptions.key = app.models.activeDay.get('id');
        this.fetch();
      },

      // Returns array of events that are done.
      completed: function () {
        return this.filter(function(event) {
          return event.isCompleted();
        });
      },

      comparator: function (event) {
        // Sort uncompleted events as if they were created a year from now.
        return event.get('completedAt') || (event.get('createdAt') + 1000*60*60*24*365);
      }

    }))()
  }
});

$.extend(true, app, {
  collections: {

    uncompletedEvents: new (Backbone.Collection.extend({

      model: app.models.Event,

      viewName: 'uncompletedEvents',

      viewOptions: {
      },

      url: (new app.models.Event().url),

      initialize: function () {
      },

      comparator: function (event) {
        return event.get('date');
      }

    }))(),

    tagsReport: new (Backbone.Collection.extend({

      model: app.models.TagReport,

      url: (new app.models.TagReport().url),

      initialize: function () {
        _.bindAll(this, 'changeDay');
        // TODO: Bind to something
      },

      changeDay: function () {
        var tagsHash = app.collections.events.completed().reduce(function (memo, event) { 
          var tag = (event.get('tag') || 'other'); 
          if (memo[tag]) {
            memo[tag] += event.get('durationSeconds');          
          } else {
            memo[tag] = event.get('durationSeconds');
          }
          return memo; 
        }, {})

        var tagsArray = _.map(tagsHash, function (v, k) {
          return {tag:k, durationSeconds:v};
        })

        app.collections.tagsReport.refresh(tagsArray);
      },

      comparator: function (tagReport) {
        return -tagReport.get('durationSeconds');
      }

    }))()

  }
});

