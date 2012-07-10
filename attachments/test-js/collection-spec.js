describe("app.collections.events", function() {

  //   beforeEach(function() {
  //   });

  describe("completed", function () {

    it("returns only completed events", function () {
      var completedEventA = new app.models.Event({ title: 'Build time tracking app #tool' });
      completedEventA.toggleCompleted();      

      var completedEventB = new app.models.Event({ title: 'Read book' });
      completedEventB.toggleCompleted();

      var eventC = new app.models.Event({ title: 'Deploy application' });

      app.collections.events.models = [
        completedEventA, completedEventB, eventC
      ];

      var completedEvents = app.collections.events.completed();
      expect(completedEvents.length).toEqual(2);
    });

  });

});

