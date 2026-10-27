/**
 * Promage Dashboard Interactive Controller
 */

// Initial Data
let projectsData = [
  { id: 1, name: "Nelsa web developement", manager: "Om prakash sao", dueDate: "May 25, 2023", status: "completed", progress: 100 },
  { id: 2, name: "Datascale AI app", manager: "Neilsan mando", dueDate: "Jun 20, 2023", status: "delayed", progress: 35 },
  { id: 3, name: "Media channel branding", manager: "Tiruvelly priya", dueDate: "July 13, 2023", status: "at-risk", progress: 68 },
  { id: 4, name: "Corlax iOS app developoement", manager: "Matte hannery", dueDate: "Dec 20, 2023", status: "completed", progress: 100 },
  { id: 5, name: "Website builder developement", manager: "Sukumar rao", dueDate: "Mar 15, 2024", status: "ongoing", progress: 50 }
];

let tasksData = [
  { id: 1, text: "Create a user flow of social application design", completed: true, status: "Approved", category: "all" },
  { id: 2, text: "Create a user flow of social application design", completed: true, status: "In review", category: "all" },
  { id: 3, text: "Landing page design for Fintech project of singapore", completed: true, status: "In review", category: "important" },
  { id: 4, text: "Interactive prototype for app screens of deltamine project", completed: false, status: "On going", category: "all" },
  { id: 5, text: "Interactive prototype for app screens of deltamine project", completed: true, status: "Approved", category: "important" }
];

let activeCategory = 'all';

document.addEventListener("DOMContentLoaded", () => {
  renderProjects();
  renderTasks();
  initSidebar();
  initSearch();
  initModal();
  animateGauge(72);
});

// Sidebar Toggle
function initSidebar() {
  const sidebar = document.getElementById("sidebar");
  const toggleBtn = document.getElementById("collapseToggle");

  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener("click", () => {
      sidebar.classList.toggle("collapsed");
    });
  }
}

// Render Projects Table
function renderProjects(filterText = "", statusFilter = "all") {
  const tbody = document.getElementById("projectTableBody");
  if (!tbody) return;

  const filtered = projectsData.filter(item => {
    const matchesSearch = item.name.toLowerCase().includes(filterText.toLowerCase()) ||
                          item.manager.toLowerCase().includes(filterText.toLowerCase());
    const matchesStatus = statusFilter === 'all' || item.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: #9CA3AF; padding: 24px;">No matching projects found</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(p => {
    const statusClass = p.status;
    const statusLabel = p.status === 'at-risk' ? 'At risk' : 
                        p.status === 'ongoing' ? 'On going' : 
                        p.status.charAt(0).toUpperCase() + p.status.slice(1);
    
    // Progress ring color
    let ringColor = '#10B981'; // green
    if (p.progress < 40) ringColor = '#F59E0B'; // yellow/amber
    else if (p.progress < 70) ringColor = '#EF4444'; // red
    else if (p.progress < 100) ringColor = '#F97316'; // orange

    const strokeDash = 2 * Math.PI * 12; // r=12
    const offset = strokeDash - (p.progress / 100) * strokeDash;

    return `
      <tr>
        <td class="project-name">${escapeHtml(p.name)}</td>
        <td class="project-manager">${escapeHtml(p.manager)}</td>
        <td class="project-date">${escapeHtml(p.dueDate)}</td>
        <td>
          <span class="status-pill ${statusClass}">${statusLabel}</span>
        </td>
        <td>
          <div class="progress-ring-wrap" title="${p.progress}% completed">
            <svg width="32" height="32" viewBox="0 0 32 32">
              <circle cx="16" cy="16" r="12" fill="none" stroke="#F3F4F6" stroke-width="2.5" />
              <circle cx="16" cy="16" r="12" fill="none" stroke="${ringColor}" stroke-width="2.5"
                stroke-dasharray="${strokeDash}" stroke-dashoffset="${offset}"
                stroke-linecap="round" transform="rotate(-90 16 16)" />
            </svg>
            <span class="progress-ring-text">${p.progress}%</span>
          </div>
        </td>
      </tr>
    `;
  }).join("");
}

// Render Tasks
function renderTasks() {
  const container = document.getElementById("taskList");
  if (!container) return;

  const filtered = activeCategory === 'all' 
    ? tasksData 
    : tasksData.filter(t => t.category === activeCategory || (activeCategory === 'important' && t.category === 'important'));

  container.innerHTML = filtered.map(t => {
    let statusBadgeClass = 'ongoing';
    if (t.status === 'Approved') statusBadgeClass = 'approved';
    else if (t.status === 'In review') statusBadgeClass = 'in-review';
    else if (t.status === 'On going') statusBadgeClass = 'ongoing';

    return `
      <div class="task-item ${t.completed ? 'checked' : ''}" data-id="${t.id}">
        <div class="task-left" onclick="toggleTask(${t.id})">
          <div class="custom-checkbox">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
          </div>
          <span class="task-text">${escapeHtml(t.text)}</span>
        </div>
        <span class="status-pill ${statusBadgeClass}">${t.status}</span>
      </div>
    `;
  }).join("");
}

// Toggle Task Complete
window.toggleTask = function(id) {
  const task = tasksData.find(t => t.id === id);
  if (task) {
    task.completed = !task.completed;
    renderTasks();
  }
};

// Filter Task by Category Tab
window.setTaskTab = function(category, btnElement) {
  activeCategory = category;
  document.querySelectorAll('.task-tab-btn').forEach(btn => btn.classList.remove('active'));
  if (btnElement) btnElement.classList.add('active');
  renderTasks();
};

// Add New Quick Task
window.addNewTask = function() {
  const input = document.getElementById("newTaskInput");
  if (!input || !input.value.trim()) return;

  const newTask = {
    id: Date.now(),
    text: input.value.trim(),
    completed: false,
    status: "On going",
    category: activeCategory === 'all' ? 'all' : activeCategory
  };

  tasksData.push(newTask);
  input.value = "";
  renderTasks();
};

// Real-time Search
function initSearch() {
  const searchInput = document.getElementById("globalSearch");
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      renderProjects(e.target.value.trim());
    });
  }
}

// Modal for Creating New Project
function initModal() {
  const modal = document.getElementById("newProjectModal");
  const openBtn = document.getElementById("openNewProjectBtn");
  const closeBtn = document.getElementById("closeModalBtn");
  const form = document.getElementById("newProjectForm");

  if (!modal) return;

  const openModal = () => modal.classList.add("open");
  const closeModal = () => modal.classList.remove("open");

  if (openBtn) openBtn.addEventListener("click", openModal);
  if (closeBtn) closeBtn.addEventListener("click", closeModal);

  modal.addEventListener("click", (e) => {
    if (e.target === modal) closeModal();
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && modal.classList.contains("open")) closeModal();
  });

  if (form) {
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const name = document.getElementById("modalProjName").value.trim();
      const manager = document.getElementById("modalProjManager").value.trim();
      const dueDate = document.getElementById("modalProjDate").value;
      const status = document.getElementById("modalProjStatus").value;
      const progress = parseInt(document.getElementById("modalProjProgress").value) || 0;

      if (!name || !manager) return;

      projectsData.unshift({
        id: Date.now(),
        name,
        manager,
        dueDate: dueDate || "TBD",
        status,
        progress: Math.min(100, Math.max(0, progress))
      });

      renderProjects();
      form.reset();
      closeModal();
    });
  }
}

// Gauge Animation
function animateGauge(targetPercent) {
  const gaugeArc = document.getElementById("gaugeArc");
  const gaugeText = document.getElementById("gaugePercentText");
  if (!gaugeArc || !gaugeText) return;

  // Arc length for r=100 semi-circle is PI * 100 ~= 314.16
  const totalLength = Math.PI * 100;
  gaugeArc.style.strokeDasharray = `${totalLength}`;
  gaugeArc.style.strokeDashoffset = `${totalLength}`;

  let current = 0;
  const duration = 1200;
  const start = performance.now();

  function step(now) {
    const progress = Math.min((now - start) / duration, 1);
    const easeProgress = 1 - Math.pow(1 - progress, 3); // ease-out cubic
    current = Math.round(easeProgress * targetPercent);
    gaugeText.textContent = `${current}%`;
    gaugeArc.style.strokeDashoffset = `${totalLength - (current / 100) * totalLength}`;

    if (progress < 1) {
      requestAnimationFrame(step);
    }
  }

  requestAnimationFrame(step);
}

// Utility: Escape HTML
function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>"']/g, function(m) {
    return {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    }[m];
  });
}
