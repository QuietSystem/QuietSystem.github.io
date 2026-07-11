let siteMenu = [];
const fileMap = {}; // Fast hash-to-filepath lookup table

// Theme Toggle Code
const toggleBtn = document.getElementById('theme-toggle');
if (localStorage.getItem('theme') === 'dark' || (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
    document.documentElement.classList.add('dark');
} else {
    document.documentElement.classList.remove('dark');
}
toggleBtn.addEventListener('click', () => {
    const isDark = document.documentElement.classList.toggle('dark');
    localStorage.setItem('theme', isDark ? 'dark' : 'light');
});

// Dynamic Dropdown Menu Builder
function buildNavigation(menuItems) {
    const navMenu = document.getElementById('nav-menu');
    navMenu.innerHTML = ''; // Clear fallback states

    menuItems.forEach(item => {
        if (item.children) {
            // Dropdown wrapper item using standard Tailwind group hov-state triggers
            const dropdownContainer = document.createElement('div');
            dropdownContainer.className = 'relative group py-2';

            dropdownContainer.innerHTML = `
                <button class="text-sm opacity-60 group-hover:opacity-100 flex items-center gap-1 transition-opacity cursor-default">
                    ${item.title} <span class="text-[10px]">▼</span>
                </button>
                <div class="absolute left-0 mt-2 w-40 origin-top-left rounded-md border border-black/10 dark:border-white/10 bg-white dark:bg-black p-1 shadow-lg opacity-0 pointer-events-none group-hover:opacity-100 group-hover:pointer-events-auto transition-all duration-150 z-50">
                    ${item.children.map(child => {
                        fileMap[child.route] = child.file;
                        return `<a href="#${child.route}" class="nav-link block px-4 py-2 text-xs rounded hover:bg-black/5 dark:hover:bg-white/5 opacity-60 transition-all">${child.title}</a>`;
                    }).join('')}
                </div>
            `;
            navMenu.appendChild(dropdownContainer);
        } else {
            // Standard Single Link
            fileMap[item.route] = item.file;
            const singleLink = document.createElement('a');
            singleLink.href = `#${item.route}`;
            singleLink.className = 'nav-link text-sm hover:opacity-60 transition-opacity';
            singleLink.textContent = item.title;
            navMenu.appendChild(singleLink);
        }
    });
}

// Router & Content Injector
async function loadContent() {
    const contentDiv = document.getElementById('content');
    if (!contentDiv) {
        console.error("CRITICAL: Could not find element with id='content' in index.html");
        return;
    }

    // Await configurations safely if the engine hasn't populated them yet
    if (siteMenu.length === 0) {
        try {
            const manifestResponse = await fetch('index.json');
            siteMenu = await manifestResponse.json();
            buildNavigation(siteMenu);
        } catch (e) {
            contentDiv.innerHTML = `<p class="text-red-500">Failed to load index.json configuration menu scheme.</p>`;
            return;
        }
    }

    // Default route mapping fallback
    let hash = window.location.hash.substring(1) || 'home';
    
    // Look up the filepath mapped during the build process
    const targetFile = fileMap[hash];
    
    if (!targetFile) {
        render404(contentDiv);
        return;
    }

    try {
        const response = await fetch(targetFile);
        if (!response.ok) throw new Error();
        const text = await response.text();
        
        // Inject parsed elements straight into your layout view container
        contentDiv.innerHTML = marked.parse(text);
        
        // Execute visual navigation highlight switches
        updateActiveState(hash);
    } catch (err) {
        render404(contentDiv);
    }
}

function updateActiveState(activeHash) {
    document.querySelectorAll('.nav-link').forEach(link => {
        const href = link.getAttribute('href');
        if (!href || !href.startsWith('#')) return;
        
        const linkHash = href.substring(1);
        
        if (linkHash.toLowerCase() === activeHash.toLowerCase()) {
            link.classList.add('font-bold', 'underline');
            link.classList.remove('opacity-60');
        } else {
            link.classList.remove('font-bold', 'underline');
            link.classList.add('opacity-60');
        }
    });
}

function render404(container) {
    container.innerHTML = `
        <h1 class="text-2xl font-bold mb-4">404 - File Not Found</h1>
        <p class="text-neutral-500">The section mapping configuration could not pull source files.</p>
    `;
}

// Initialization Hooks
window.addEventListener('hashchange', loadContent);
window.addEventListener('DOMContentLoaded', loadContent);
