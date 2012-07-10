if ((typeof app) === 'undefined') {
  var app = {};
}

$.extend(true, app, {
  views: {

    AppView: Backbone.View.extend({

      el: $('#container'),

      initialize: function () {
        _.bindAll(this, 'render');

        app.models.activeDay.bind('change', this.render);
      },

      render: function () {
        $('#container').empty();

        new app.views.ClockView({
          model: (new app.models.Clock()),
          parentView: this.el
        });

        var view = new app.views.DayView({
          model: app.models.activeDay,
          parentView: this.el
        });
      }

    }),

    ClockView: app.views.prototypes.AbstractView.extend({

      className: 'view ClockView',

      template: Handlebars.compile($('#template-clock-view').html()),

      afterInitialize: function () {
        var self = this;
        $(this.parentView).append(this.el);

        app.collections.events.bind('refresh', this.render);
        app.collections.events.bind('add',     this.render);
        app.collections.events.bind('remove',  this.render);

        // The clock needs to update frequently, even if the models don't.
        window.setInterval(function() { self.render(); }, 10*1000);
      },

      render: function () {
        var attr = {
          totalTime: this.model.totalTime(),
          elapsedTime: this.model.elapsedTime()
        };

        $(this.el).html(this.template(attr));
        return this;
      }

    }),

    TagReportView: app.views.prototypes.AbstractView.extend({

      className: 'view TagReportView',

      template: Handlebars.compile($('#template-tag-report-view').html()),

      afterInitialize: function () {
        var self = this;
        $(this.parentView).find('.tags').first().append(this.el);

        app.collections.tagsReport.bind('refresh', this.render);
        app.collections.tagsReport.bind('add',     this.render);
      },

      render: function () {
        var attr = {
          tags: app.collections.tagsReport.map(function (item) {
            return item.toJSON();
          })
        };

        $(this.el).html(this.template(attr));
        return this;
      }

    }),

    DayView: app.views.prototypes.AbstractView.extend({

      className: 'view DayView',

      template: Handlebars.compile($('#template-day-view').html()),

      afterInitialize: function () {
        $(this.parentView).append(this.el);

        app.collections.events.bind('refresh', this.render);
        app.collections.events.bind('add',     this.render);
        app.collections.events.bind('remove',  this.render);
      },

      events: {
        'keypress #new_event': 'saveOnEnter',
        'click #previous': 'goToPrevious',
        'click #next': 'goToNext'
      },

      render: function () {
        var attr = this.model.toJSON();

        $(this.el).html(this.template(attr));

        var tagReport = new app.views.TagReportView({
          parentView: this.el
        });

        console.log('Events: ', app.collections.events.models.length);
        app.collections.events.each(this.addOne);

        $('#new_event').focus();

        app.collections.tagsReport.changeDay();

        app.keys.setup();

        return this;
      },

      addOne: function (event) {
        var view = new app.views.EventView({
          model: event,
          parentView: this.el
        });
      },

      saveOnEnter: function(e) {
        if (e.keyCode == 13) {
          app.collections.events.create({
            title: $('#new_event').val(),
            date: app.models.activeDay.get('id')
          });

          $('#new_event').val('').focus();
        }
      },

      goToPrevious: function () {
        window.location.hash = "#" + app.models.activeDay.previousId();
      },

      goToNext: function () {
        window.location.hash = "#" + app.models.activeDay.nextId();
      }

    }),

    EventView: app.views.prototypes.AbstractView.extend({

      tagName: 'li',

      className: 'view EventView',

      template: Handlebars.compile($('#template-event-view').html()),

      afterInitialize: function () {
        $(this.parentView).find('.events').first().append(this.el);
      },

      events: {
        'click .toggle':     'toggleCompleted',
        'click .edit':       'edit',
        'click .delete':     'destroy',
        'mouseover':         'hoverOn',
        'mouseout':          'hoverOff',
        'keypress .editing': 'saveOnEnter'
      },

      render: function () {
        var attr = this.model.toJSON();

        $(this.el).html(this.template(attr));

        return this;
      },

      toggleCompleted: function () {
        if (this.model.isCompleted()) {
          if (!confirm("Do you want to clear this event's time?")) {
            return false;
          }
        }
        this.model.toggleCompleted();
        this.model.save();

        this.render();
      },

      edit: function () {
        var editDiv = $(this.el).find('.editing')
        editField = editDiv.find('input.edit_event');

        editField.val(this.model.get('rawTitle'));

        editDiv.show();
        $(this.el).find('.buttons').hide();
        editField.focus();
      },

      saveOnEnter: function (e) {
        if (e.keyCode == 13) {
          this.model.setTitle($(this.el).find('.edit_event').val());
          this.model.save();

          $(this.el).find('.editing').hide();
          $('#new_event').focus();
        }
      },

      destroy: function () {
        if (confirm("Do you want to delete this event?\n\n'" + this.model.get('title') + "'")) {
          app.collections.events.remove(this.model);
          this.model.destroy();
        }
      },

      hoverOn: function () {
        $(this.el).find('.buttons').show()
      },

      hoverOff: function () {
        $(this.el).find('.buttons').hide();
      }

    }),

    UncompletedView: Backbone.View.extend({

      el: $('#container'),

      template: Handlebars.compile($('#template-uncompleted-view').html()),

      initialize: function () {
        _.bindAll(this, 'render', 'addOne');

        app.collections.uncompletedEvents.bind('refresh', this.render);
        app.collections.uncompletedEvents.bind('add',     this.render);
        app.collections.uncompletedEvents.bind('remove',  this.render);
      },

      render: function () {
        var attr = {};
        $(this.el).html(this.template(attr));

        console.log('Rendering UncompletedView');
        
        app.collections.uncompletedEvents.each(this.addOne);
      },

      addOne: function (event) {
        var view = new app.views.EventView({
          model: event,
          parentView: this.el
        });
      }

    })

  }
});

