describe("app.models.Event", function() {

  describe("tag", function () {

    it("extracts tag from title", function () {
      var event = new app.models.Event({ title: 'Build time tracking app #tool' });
      expect(event.get('tag')).toEqual('tool');
    });

    it("resets tag if removed from title", function () {
      var event = new app.models.Event();
      event.setTitle('Build time tracking app #tool');
      expect(event.get('tag')).toEqual('tool');

      event.setTitle('No tag this time');
      expect(event.get('tag')).toEqual(null);
    });

    it("populates rawTitle from title", function () {
      var event = new app.models.Event({ title: 'Build time tracking app #tool' });
      expect(event.get('rawTitle')).toEqual('Build time tracking app #tool');
    });

    it("removes tag text from title", function () {
      var event = new app.models.Event({ title: 'Build time tracking app #tool' });
      expect(event.get('title')).toEqual('Build time tracking app');
    });


    describe("automatic tagging", function () {

      it("detects a keyword", function () {
        var event = new app.models.Event();
        event.setTitle('Reply to email');
        expect(event.get('tag')).toEqual('email');
      });

      it("is case insensitive", function () {
        var event = new app.models.Event();
        event.setTitle('Reply to EMAIL');
        expect(event.get('tag')).toEqual('email');
      });

      it("does not tag if nothing matches", function () {
        var event = new app.models.Event();
        event.setTitle('Bacon');
        expect(event.get('tag')).toEqual(null);
      });

      it("matches only whole words", function () {
        var event = new app.models.Event();
        event.setTitle('Emailizzle');
        expect(event.get('tag')).toEqual(null);
      });

    });

  });

  describe("completed", function () {

    describe("toggleCompleted", function () {

      beforeEach(function() {
        this.event = new app.models.Event({ title: 'Build time tracking app #tool' });
      });

      it("populates completedAt", function () {
        this.event.toggleCompleted();

        expect(typeof this.event.get('completedAt')).toEqual('number');
      });

      it("registers as completed", function () {
        this.event.toggleCompleted();

        expect(this.event.isCompleted()).toBeTruthy();
      });

      it("starts as not completed", function () {
        expect(this.event.isCompleted()).toBeFalsy();
      });

      it("goes back to not completed", function () {
        this.event.toggleCompleted();
        this.event.toggleCompleted();

        expect(this.event.isCompleted()).toBeFalsy();
      });

    });

    describe("duration", function () {

      beforeEach(function () {
        this.completedEventA = new app.models.Event({ title: 'Build time tracking app #tool' });
        this.completedEventA.toggleCompleted();

        this.completedEventB = new app.models.Event({ title: 'Read book' });
        this.completedEventB.toggleCompleted();
        // Set to 35 minutes ago for duration calculation.
        this.completedEventB.set({ completedAt: (new Date()).getTime() - (60*35*1000) });

        this.eventC = new app.models.Event({ title: 'Deploy application' });

        this.eventD = new app.models.Event({ title: 'Write report' });

        app.collections.events.models = [
          this.completedEventA, this.completedEventB, this.eventC, this.eventD
        ];
      });

      it("calculates time from last completed event", function () {
        this.eventD.toggleCompleted();

        expect(this.eventD.get('duration')).toEqual(':35');
      });

      it("resets duration if event is not done", function () {
        this.eventD.toggleCompleted();
        this.eventD.toggleCompleted();

        expect(this.eventD.get('duration')).toEqual(null);
      });

    });

    describe("duration with single event", function () {

      beforeEach(function () {
        this.eventA = new app.models.Event({ title: 'Build time tracking app #tool' });
        this.eventC = new app.models.Event({ title: 'Deploy application' });
        this.eventD = new app.models.Event({ title: 'Write report' });

        app.collections.events.models = [
          this.eventA, this.eventC, this.eventD
        ];
      });

      it("calculates time from last completed event", function () {
        this.eventA.toggleCompleted();

        expect(this.eventA.get('duration')).toEqual('•');
      });

    });

  });

});

