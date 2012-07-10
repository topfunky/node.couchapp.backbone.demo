
if ((typeof app) === 'undefined') {
  var app = {};
}

$.extend(true, app, {
  models: {

    // Non-persistent model that represents the day being viewed.
    activeDay: new(Backbone.Model.extend({

      url: '/day',

      initialize: function () {
        if (!this.attributes.id) {
          var date = new Date();
          this.attributes.date = date;
          this.attributes.name = date.strftime('%A');
          this.attributes.id = date.strftime('%Y-%m-%d');
        }
      },

      resetToToday: function () {
        this.setFromDate(new Date());
      },

      setFromDate: function (date) {
        this.set({
          date: date,
          name: date.strftime('%A'),
          id: date.strftime('%Y-%m-%d')
        });
      },

      setFromDateString: function (dateString) {
        var parts = dateString.split('-'),
          date = null;
        if (parts.length && parts.length == 3) {
          date = new Date(parts[0], parts[1]-1, parts[2]);
          this.setFromDate(date);
        }
      },

      // Returns a formatted date string like '2011-03-21'
      previousId: function () {
        return new Date(this.get('date').getTime() - 1000 * 60 * 60 * 24).strftime('%Y-%m-%d');
      },

      // Returns a formatted date string like '2011-03-21'
      nextId: function () {
        return new Date(this.get('date').getTime() + 1000 * 60 * 60 * 24).strftime('%Y-%m-%d');
      }

    }))(),

    // Non-persistent model for time calculations only.
    Clock: Backbone.Model.extend({

      totalTime: function () {
        var events = app.collections.events.completed(),
          first = null,
          last = null,
          seconds = 0;

        if (events.length > 1) {
          first = _.first(events);
          last = _.last(events);

          seconds = (last.get('completedAt') - first.get('completedAt')) / 1000;

          return app.util.secondsToTimeString(seconds);
        }

        return '•';
      },

      elapsedTime: function () {
        var events = app.collections.events.completed(),
          last = null,
          now = (new Date()).getTime(),
          seconds = 0;

        if (events.length > 0) {
          last = _.last(events);

          seconds = (now - last.get('completedAt')) / 1000;

          // More than 20 hours is meaningless.
          if (seconds > (24*60*60)) {
            return '–';
          }

          return app.util.secondsToTimeString(seconds);
        }

        return '•';
      }

    }),

    Event: Backbone.Model.extend({

      url: '/event',

      defaults: {
        title: '',
        tag: '',
        duration: ''
      },

      initialize: function () {
        if (!this.attributes.createdAt) {
          this.attributes.createdAt = (new Date()).getTime();
        }
        if (this.attributes.title && !this.attributes.rawTitle) {
          this.setTitle(this.attributes.title);
        }
      },

      setTitle: function (theTitle) {
        this.set({
          title: theTitle,
          rawTitle: theTitle
        });
        this.parseTag();
      },

      parseTag: function () {
        if (this.get('rawTitle')) {
          var matches = this.get('rawTitle').match(/ #(\w+)/);
          if (matches && matches.length > 1) {
            this.set({
              tag: matches[1],
              title: this.get('rawTitle').split(/ #/)[0]
            });
            return;
          } else {
            var autotags = {
              email: /\b(email)\b/i,
              eat: /\b(breakfast|lunch|dinner|snack|eat)\b/i
            };

            var didAutotag = _.detect(autotags, function (regex, tag) {
              if (this.get('rawTitle').match(regex)) {
                this.set({
                  tag: tag
                });
                return true;
              }
              return false;
            }, this);
            if (didAutotag) {
              return;
            }
          }
        }
        this.attributes.tag = null;
      },

      toggleCompleted: function () {
        if (this.isCompleted()) {
          this.set({
            completedAt: null,
            duration: null,
            durationSeconds: null
          });
        } else {
          var completedAt = (new Date()).getTime(),
            previousEvent = null,
            duration = null,
            diffInSeconds = 0;

          previousEvent = _.last(app.collections.events.completed());

          if (previousEvent) {
            diffInSeconds = parseInt((completedAt - previousEvent.get('completedAt')) / 1000, 10);
            duration = app.util.secondsToTimeString(diffInSeconds);
          } else {
            diffInSeconds = 0;
            duration = '•';
          }

          this.set({
            completedAt: completedAt,
            duration: duration,
            durationSeconds: diffInSeconds
          });
        }
        app.collections.events.sort();
      },

      isCompleted: function () {
        return typeof this.get('completedAt') === 'number';
      }

    }),

    TagReport: Backbone.Model.extend({

      url: '/tagReport',

      defaults: {
        tag: '',
        durationSeconds: 0
      },

      initialize: function () {
        if (!this.attributes.duration) {
          this.attributes.duration = app.util.secondsToTimeString(this.attributes.durationSeconds);
        }
      }

    })

  }
});
