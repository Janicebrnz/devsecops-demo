pipeline {
    agent any
    options { timestamps(); buildDiscarder(logRotator(numToKeepStr: '10')) }

    environment {
        PY      = 'C:\\Users\\barne\\AppData\\Local\\Programs\\Python\\Python312\\python.exe'
        GH_REPO = 'github.com/Janicebrnz/Devops.git'
        GH_CRED = 'github-creds'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                bat '%PY% --version'
                bat 'if not exist reports mkdir reports'
            }
        }

        stage('SAST: OWASP Scan') {
            steps {
                script {
                    env.SCAN_RC = bat(script: '@%PY% security/owasp_scan.py --report reports/before',
                                      returnStatus: true).toString()
                }
            }
        }

        stage('Auto-Remediate') {
            when { expression { env.SCAN_RC != '0' } }
            steps {
                bat '%PY% security/owasp_scan.py --fix'
                bat 'git diff > reports\\fixes.patch'
                bat 'type reports\\fixes.patch'
            }
        }

        stage('Re-Scan Gate') {
            when { expression { env.SCAN_RC != '0' } }
            steps {
                bat '%PY% security/owasp_scan.py --report reports/after'
                unstable('Vulnerabilities were found and auto-remediated')
            }
        }

        stage('Security Regression Tests') {
            steps { bat '%PY% -m unittest discover -s tests -v' }
        }

        stage('Push Fix Branch') {
            when { expression { env.SCAN_RC != '0' } }
            steps {
                withCredentials([usernamePassword(credentialsId: env.GH_CRED,
                                 usernameVariable: 'GH_USER', passwordVariable: 'GH_TOKEN')]) {
                    bat '''
                        git config user.email "jenkins-bot@example.com"
                        git config user.name "Jenkins DevSecOps Bot"
                        git checkout -B security-autofix
                        git add -A
                        git commit -m "security: auto-remediate OWASP findings" || echo nothing to commit
                        git push -f https://%GH_USER%:%GH_TOKEN%@%GH_REPO% security-autofix
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
