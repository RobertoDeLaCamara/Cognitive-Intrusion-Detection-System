pipeline {
    agent { label 'agent-45' }

    options {
        buildDiscarder(logRotator(numToKeepStr: '5'))
        timestamps()
        timeout(time: 60, unit: 'MINUTES')
    }

    environment {
        REGISTRY   = "192.168.1.147:5000"
        IMAGE_NAME = "cnds"
        NO_PROXY   = 'localhost,127.0.0.1,192.168.1.0/24,192.168.1.147,192.168.1.62,192.168.1.45'
        no_proxy   = 'localhost,127.0.0.1,192.168.1.0/24,192.168.1.147,192.168.1.62,192.168.1.45'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build Image') {
            steps {
                echo 'Building Docker image...'
                sh "docker build -t ${REGISTRY}/${IMAGE_NAME}:${env.BUILD_NUMBER} -t ${REGISTRY}/${IMAGE_NAME}:latest ."
            }
        }

        stage('Code Quality') {
            parallel {
                stage('Lint') {
                    steps {
                        sh """
                        docker run --rm --user root \
                            ${REGISTRY}/${IMAGE_NAME}:${env.BUILD_NUMBER} \
                            sh -c 'pip install --quiet flake8 && flake8 src/ --max-line-length=120 --count --statistics || true'
                        """
                    }
                }
                stage('Security') {
                    steps {
                        sh """
                        docker run --rm --user root \
                            ${REGISTRY}/${IMAGE_NAME}:${env.BUILD_NUMBER} \
                            sh -c 'pip install --quiet safety && safety check -r requirements.txt --full-report || true'
                        """
                    }
                }
            }
        }

        stage('Run Tests') {
            steps {
                script {
                    try {
                        sh """
                        docker run --name test-cnds-${env.BUILD_NUMBER} \
                            --user root \
                            -e DATABASE_URL=sqlite+aiosqlite:////tmp/test.db \
                            ${REGISTRY}/${IMAGE_NAME}:${env.BUILD_NUMBER} \
                            python -m pytest tests/ -v \
                                --junitxml=test-results.xml \
                                --cov=src \
                                --cov-report=xml:coverage.xml \
                                --cov-report=term-missing \
                                --disable-warnings
                        """
                    } finally {
                        sh "docker cp test-cnds-${env.BUILD_NUMBER}:/app/test-results.xml ${env.WORKSPACE}/test-results.xml || true"
                        sh "docker cp test-cnds-${env.BUILD_NUMBER}:/app/coverage.xml ${env.WORKSPACE}/coverage.xml || true"
                        sh "docker rm test-cnds-${env.BUILD_NUMBER} || true"
                    }
                }
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'test-results.xml'
                    archiveArtifacts artifacts: 'coverage.xml', allowEmptyArchive: true, fingerprint: true
                }
            }
        }

        stage('SonarQube Analysis') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'sonarqube-credentials',
                    usernameVariable: 'SONAR_USER',
                    passwordVariable: 'SONAR_PASS'
                )]) {
                    sh """
                        VOL="cnds-sonar-${env.BUILD_NUMBER}"
                        docker volume create "\$VOL"
                        tar -cf - . | docker run --rm -i -v "\$VOL:/usr/src" alpine tar -xf - -C /usr/src
                        docker run --rm \
                            -e SONAR_USER="\$SONAR_USER" \
                            -e SONAR_PASS="\$SONAR_PASS" \
                            -v "\$VOL:/usr/src" \
                            sonarsource/sonar-scanner-cli \
                            -Dsonar.projectKey=cnds \
                            -Dsonar.sources=src \
                            -Dsonar.tests=tests \
                            -Dsonar.python.version=3.11 \
                            -Dsonar.python.coverage.reportPaths=coverage.xml \
                            -Dsonar.host.url=http://192.168.1.147:9000 \
                            -Dsonar.login="\$SONAR_USER" \
                            -Dsonar.password="\$SONAR_PASS" \
                            -Dsonar.scm.disabled=true
                        docker volume rm "\$VOL"
                    """
                }
            }
        }

        stage('Push to Registry') {
            steps {
                echo "Pushing image to ${REGISTRY}..."
                sh "docker push ${REGISTRY}/${IMAGE_NAME}:${env.BUILD_NUMBER}"
                sh "docker push ${REGISTRY}/${IMAGE_NAME}:latest"
            }
        }

        // ── arm64 build (disabled — requires raspi-62 as Jenkins agent) ──────
        // To enable: add raspi-62 (Pi 5, aarch64) as a Jenkins agent with
        // label 'raspi-62', then uncomment this stage. Uses classic docker build
        // (not buildx) so --build-arg TARGETARCH=arm64 must be passed explicitly.
        //
        // stage('Build Image arm64') {
        //     agent { label 'raspi-62' }
        //     steps {
        //         checkout scm
        //         sh """
        //             docker build \
        //                 --build-arg TARGETARCH=arm64 \
        //                 -t ${REGISTRY}/${IMAGE_NAME}:${env.BUILD_NUMBER}-arm64 \
        //                 -t ${REGISTRY}/${IMAGE_NAME}:latest-arm64 \
        //                 .
        //         """
        //         sh "docker push ${REGISTRY}/${IMAGE_NAME}:${env.BUILD_NUMBER}-arm64"
        //         sh "docker push ${REGISTRY}/${IMAGE_NAME}:latest-arm64"
        //     }
        // }
    }

    post {
        always {
            sh 'rm -f test-results.xml coverage.xml || true'
            sh "docker rmi ${REGISTRY}/${IMAGE_NAME}:${env.BUILD_NUMBER} || true"
            sh "docker volume rm cnds-sonar-${env.BUILD_NUMBER} || true"
            cleanWs()
        }
        success {
            echo 'Pipeline succeeded!'
        }
        failure {
            echo 'Pipeline failed.'
        }
    }
}
