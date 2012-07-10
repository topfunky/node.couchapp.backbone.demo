describe("app.models.Clock", function () {

  describe("without events", function () {

    beforeEach(function () {
      app.collections.events.models = [];
    });

    it("returns zero for totalTime", function () {
      var clock = new app.models.Clock();

      expect(clock.totalTime()).toEqual('•');
    });

    it("calculates zero since last logged event", function () {
      var clock = new app.models.Clock();

      expect(clock.elapsedTime()).toEqual('•');
    });

  });


  describe("with events", function () {

    beforeEach(function () {
      this.completedEventA = new app.models.Event({ title: 'Build time tracking app #tool' });
      this.completedEventA.toggleCompleted();
      // Set to some time ago for calculations.
      this.completedEventA.set({ completedAt: (new Date()).getTime() - (60*195*1000) });

      this.completedEventB = new app.models.Event({ title: 'Read book' });
      this.completedEventB.toggleCompleted();
      // Set to some time ago for calculations.
      this.completedEventB.set({ completedAt: (new Date()).getTime() - (60*10*1000) });

      this.eventC = new app.models.Event({ title: 'Deploy application' });

      this.eventD = new app.models.Event({ title: 'Write report' });

      app.collections.events.models = [
        this.completedEventA, this.completedEventB, this.eventC, this.eventD
      ];
    });

    it("calculates total time", function () {
      var clock = new app.models.Clock();

      expect(clock.totalTime()).toEqual('3:05');
    });

    it("calculates time since last logged event", function () {
      var clock = new app.models.Clock();

      expect(clock.elapsedTime()).toEqual(':10');
    });

  });

});
