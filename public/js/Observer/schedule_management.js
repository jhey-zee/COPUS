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

  document.addEventListener('DOMContentLoaded', function() {
  const searchInput = document.getElementById('searchInput');
  const table = document.querySelector('.custom-table');
  const tbody = table.tBodies[0];
  const rows = Array.from(tbody.rows);
  const rowsPerPage = 8;
  let currentPage = 1;

  // Create pagination container
  const paginationContainer = document.createElement('div');
  paginationContainer.className = 'pagination-container';
  table.parentNode.insertBefore(paginationContainer, table.nextSibling);

  function renderTable(filteredRows, page) {
    tbody.innerHTML = '';
    const start = (page - 1) * rowsPerPage;
    const end = start + rowsPerPage;
    const pageRows = filteredRows.slice(start, end);
    pageRows.forEach(row => tbody.appendChild(row));
  }

  function renderPagination(filteredRows) {
    paginationContainer.innerHTML = '';
    const pageCount = Math.ceil(filteredRows.length / rowsPerPage);
    if (pageCount <= 1) return; // no pagination needed

    for(let i = 1; i <= pageCount; i++) {
      const btn = document.createElement('button');
      btn.className = 'pagination-btn';
      btn.textContent = i;
      if(i === currentPage) btn.classList.add('active');
      btn.addEventListener('click', () => {
        currentPage = i;
        renderTable(filteredRows, currentPage);
        renderPagination(filteredRows);
      });
      paginationContainer.appendChild(btn);
    }
  }

  function filterRows() {
    const query = searchInput.value.toLowerCase();
    return rows.filter(row => {
      return Array.from(row.cells).some(cell => cell.textContent.toLowerCase().includes(query));
    });
  }

  function updateTable() {
    const filteredRows = filterRows();
    currentPage = 1;
    renderTable(filteredRows, currentPage);
    renderPagination(filteredRows);
  }

  searchInput.addEventListener('input', updateTable);

  // Initialize
  updateTable();
});


  