pipeline {
    agent any
    options { timestamps(); buildDiscarder(logRotator(numToKeepStr: '10')) }

    environment {
        // CHANGE THESE TWO
        GH_REPO = 'github.com/Janicebrnz/devsecops-demo.git'
        GH_CRED = 'github-creds'        // Jenkins "Username with password" credential (PAT as password)
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                sh 'python3 --version && mkdir -p reports'
            }
        }

        stage('SAST: OWASP Scan') {
            steps {
                script {
                    env.SCAN_RC = sh(script: 'python3 security/owasp_scan.py --report reports/before',
                                     returnStatus: true).toString()
                }
            }
        }

        stage('Auto-Remediate') {
            when { expression { env.SCAN_RC != '0' } }
            steps {
                sh 'python3 security/owasp_scan.py --fix'
                sh 'git diff > reports/fixes.patch || true'
                sh 'cat reports/fixes.patch'
            }
        }

        stage('Re-Scan Gate') {
            when { expression { env.SCAN_RC != '0' } }
            steps {
                // Fails the build if anything that needs a human fix is still present
                sh 'python3 security/owasp_scan.py --report reports/after'
                unstable('Vulnerabilities were found and auto-remediated')
            }
        }

        stage('Security Regression Tests') {
            steps { sh 'python3 -m unittest discover -s tests -v' }
        }

        stage('Push Fix Branch') {
            when { expression { env.SCAN_RC != '0' } }
            steps {
                withCredentials([usernamePassword(credentialsId: env.GH_CRED,
                                 usernameVariable: 'GH_USER', passwordVariable: 'GH_TOKEN')]) {
                    sh '''
                        git config user.email "jenkins-bot@example.com"
                        git config user.name  "Jenkins DevSecOps Bot"
                        git checkout -B security-autofix
                        git add -A
                        git commit -m "security: auto-remediate OWASP findings" || true
                        git push -f https://${GH_USER}:${GH_TOKEN}@${GH_REPO} security-autofix
                    '''
                }
            }
        }

        stage('Deploy') {
            steps { echo 'All security gates passed. Deploying (simulated)...' }
        }
    }

    post {
        always  { archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true }
        failure { echo 'BLOCKED: unresolved vulnerabilities or failing tests. See reports/after/report.html' }
    }
}
