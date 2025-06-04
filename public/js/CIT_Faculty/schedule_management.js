document.addEventListener("DOMContentLoaded", function () {
    const addUserBtn = document.querySelector(".create-account-icon");
    const scheduleManagementView = document.getElementById("scheduleManagementView");
    const addScheduleView = document.getElementById("addScheduleView");
    const cancelBtn = document.getElementById("cancelAddSchedule");
  
    if (addUserBtn) {
      addUserBtn.addEventListener("click", function () {
        scheduleManagementView.style.display = "none";
        addScheduleView.style.display = "block";
      });
    }
  
    if (cancelBtn) {
      cancelBtn.addEventListener("click", function () {
        addScheduleView.style.display = "none";
        scheduleManagementView.style.display = "block";
      });
    }
  });

  document.querySelectorAll('.edit-btn').forEach(button => {
    button.addEventListener('click', () => {
      const schedule = JSON.parse(button.getAttribute('data-schedule'));
      
      document.getElementById('edit-id').value = schedule._id;
      document.getElementById('edit-firstname').value = schedule.firstname;
      document.getElementById('edit-lastname').value = schedule.lastname;
      // Populate other fields similarly...
      
      document.getElementById('editScheduleForm').action = `/schedule/update/${schedule._id}`;
    });
  });

  // hello

  