// Jenkinsfile - Pipeline de "Sistema Alumnos" (SecureDev · Evaluación Parcial 3 · OCY1102)
// Build -> Test -> SAST (Bandit) -> Dependencias (pip-audit) -> Staging -> DAST (OWASP ZAP) -> Producción (con gate)
pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 40, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    // Revisa GitHub cada ~3 minutos: cada push (tuyo o un PR de Dependabot fusionado) dispara un build.
    triggers {
        pollSCM('H/3 * * * *')
    }

    environment {
        PIP_DISABLE_PIP_VERSION_CHECK = '1'
        ZAP_MINUTOS_ACTIVO = '3'
    }

    stages {
        stage('Build') {
            steps {
                script {
                    // Versión = 1.0.<nº de build>+<commit corto>: une cada despliegue con su commit (trazabilidad)
                    def sha = sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
                    env.APP_VERSION = "1.0.${env.BUILD_NUMBER}+${sha}"
                }
                echo "Versión de este build: ${env.APP_VERSION}"
                sh 'git log -1 --format="Commit %h de %an: %s"'
                sh 'rm -rf .venv reports && mkdir -p reports'
                sh 'python3 -m venv .venv'
                sh '.venv/bin/pip install --quiet -r requirements.txt -r requirements-dev.txt'
                sh '.venv/bin/python -m compileall -q app.py'
            }
        }

        stage('Test') {
            steps {
                sh '.venv/bin/python -m pytest --junitxml=reports/junit.xml'
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'reports/junit.xml'
                }
            }
        }

        // Revisión de código (SAST) con Bandit
        stage('Security Review (SAST)') {
            steps {
                sh 'bandit -r app.py -f json -o reports/bandit.json || true'
                sh 'bandit -r app.py -f txt -o reports/bandit.txt || true'
                sh 'cat reports/bandit.txt'
                script {
                    if (sh(returnStatus: true, script: 'bandit -q -ll app.py') != 0) {
                        unstable('Bandit encontró hallazgos Medium/High')
                    }
                }
            }
        }

        // Revisión de dependencias (SCA) con pip-audit
        stage('Dependency Management') {
            steps {
                script {
                    def rc = sh(returnStatus: true, script: 'pip-audit -r requirements.txt -f json -o reports/pip-audit.json')
                    sh 'pip-audit -r requirements.txt > reports/pip-audit.txt 2>&1 || true; cat reports/pip-audit.txt'
                    if (rc != 0) {
                        unstable('pip-audit encontró dependencias vulnerables')
                    }
                }
            }
        }

        // Despliegue en staging (puerto 5001) para que ZAP lo escanee
        stage('Deploy Staging') {
            steps {
                sh 'bash scripts/deploy.sh staging 5001'
            }
        }

        // Pruebas dinámicas (DAST) con OWASP ZAP sobre staging
        stage('DAST - OWASP ZAP') {
            steps {
                script {
                    def rc = sh(returnStatus: true, script: 'python3 scripts/zap_scan.py http://jenkins:5001')
                    if (rc == 2) {
                        unstable('OWASP ZAP encontró alertas High/Medium')
                    } else if (rc != 0) {
                        error('Falló el escaneo de OWASP ZAP')
                    }
                }
            }
        }

        stage('Deploy Producción') {
            // GATE: solo se despliega si todas las revisiones de seguridad salieron limpias
            when {
                expression { currentBuild.currentResult == 'SUCCESS' }
            }
            steps {
                sh 'bash scripts/deploy.sh produccion 5000'
                script { env.PRODUCCION = env.APP_VERSION }
            }
        }
    }

    post {
        always {
            // Registro de trazabilidad: build <-> versión <-> commit <-> pruebas <-> hallazgos <-> despliegue
            withEnv(["RESULTADO=${currentBuild.currentResult}"]) {
                sh 'python3 scripts/trazabilidad.py'
            }
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
    }
}
