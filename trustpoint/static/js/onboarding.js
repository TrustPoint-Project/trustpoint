function getOnboardingState(urlExt) {
  fetch('/rest/provision/state/'+ urlExt)
    .then(response => response.json())
    .then(data => {
      console.log(data);
    }
  );
}
