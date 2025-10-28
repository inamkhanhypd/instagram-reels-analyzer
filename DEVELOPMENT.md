# Development Workflow

## Branch Strategy

### 🌿 **Main Branches**
- **`main`** - Production branch (deployed to Railway)
- **`develop`** - Development branch (for testing new features)

### 🔄 **Development Workflow**

#### **1. Development Phase**
```bash
# Switch to develop branch
git checkout develop

# Create feature branch from develop
git checkout -b feature/new-feature-name

# Make your changes
# ... code changes ...

# Commit changes
git add .
git commit -m "feat: add new feature description"

# Push feature branch
git push origin feature/new-feature-name
```

#### **2. Testing Phase**
```bash
# Test locally on develop branch
git checkout develop
git merge feature/new-feature-name

# Test the application locally
streamlit run app.py

# If everything looks good, push to develop
git push origin develop
```

#### **3. Production Deployment**
```bash
# Switch to main branch
git checkout main

# Merge develop into main
git merge develop

# Push to main (triggers Railway deployment)
git push origin main

# Clean up feature branch
git branch -d feature/new-feature-name
git push origin --delete feature/new-feature-name
```

## 🚀 **Deployment Strategy**

### **Railway Configuration**
- **Production**: `main` branch → Auto-deploys to Railway
- **Development**: `develop` branch → Available for testing

### **Version Management**
- Update `version.py` with new version number
- Include changelog for each release
- Tag releases: `git tag v1.2.3`

## 📋 **Best Practices**

### **Commit Messages**
- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `style:` - Code formatting
- `refactor:` - Code refactoring
- `test:` - Adding tests
- `chore:` - Maintenance tasks

### **Testing Checklist**
- [ ] Code compiles without errors
- [ ] Streamlit app runs locally
- [ ] All features work as expected
- [ ] No console errors or warnings
- [ ] UI/UX is intuitive
- [ ] Performance is acceptable

### **Before Merging to Main**
- [ ] All tests pass
- [ ] Code is reviewed
- [ ] Version number updated
- [ ] Changelog updated
- [ ] No breaking changes

## 🔧 **Local Development Setup**

```bash
# Install dependencies
pip install -r requirements.txt

# Run development server
streamlit run app.py

# Run with specific port
streamlit run app.py --server.port 8502
```

## 📝 **Current Status**
- **Current Branch**: `develop`
- **Production**: `main` (v1.2.2)
- **Next Version**: v1.2.3 (in development)
