$.extend(true, app, {
  views: {
    prototypes: {

      AbstractView: Backbone.View.extend({

        initialize: function(opts) {
          _.bindAll(this, 'addOne', 'render', 'close');
          if (this.model) {
            this.model.bind('change', this.render);
          }

          this.parentView = opts.parentView;

          if (typeof this.afterInitialize === 'function') {
            this.afterInitialize.apply(this);
          }

          this.render();
        }

      })
    }
  }
});

