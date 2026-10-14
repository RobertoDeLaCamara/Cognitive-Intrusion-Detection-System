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
        // Multibranch: master (or the legacy single-branch job, BRANCH_NAME unset) keeps the
        // build-number tag; other branches/PRs get "<branch>-<build>" and are never pushed.
        IMAGE_TAG  = "${(env.BRANCH_NAME == null || env.BRANCH_NAME == 'master') ? env.BUILD_NUMBER : env.BRANCH_NAME.replaceAll('[^A-Za-z0-9_.-]', '-') + '-' + env.BUILD_NUMBER}"
        NO_PROXY   = 'localhost,127.0.0.1,192.168.1.0/24,192.168.1.147,192.168.1.62'
        no_proxy   = 'localhost,127.0.0.1,192.168.1.0/24,192.168.1.147,192.168.1.62'
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
                sh "docker build -t ${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG} ."
            }
        }

        stage('Code Quality') {
            parallel {
                stage('Lint') {
                    steps {
                        sh """
                        docker run --rm --user root \
                            ${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG} \
                            sh -c 'pip install --quiet flake8 && flake8 src/ --max-line-length=120 --count --statistics || true'
                        """
                    }
                }
                stage('Security') {
                    steps {
                        sh """
                        docker run --rm --user root \
                            ${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG} \
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
                        docker run --name test-cnds-${IMAGE_TAG} \
                            --user root \
                            -e DATABASE_URL=sqlite+aiosqlite:////tmp/test.db \
                            ${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG} \
                            python -m pytest tests/ -v \
                                --junitxml=test-results.xml \
                                --cov=src \
                                --cov-report=xml:coverage.xml \
                                --cov-report=term-missing \
                                --disable-warnings
                        """
                    } finally {
                        sh "docker cp test-cnds-${IMAGE_TAG}:/app/test-results.xml ${env.WORKSPACE}/test-results.xml || true"
                        sh "docker cp test-cnds-${IMAGE_TAG}:/app/coverage.xml ${env.WORKSPACE}/coverage.xml || true"
                        sh "docker rm test-cnds-${IMAGE_TAG} || true"
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
                        VOL="cnds-sonar-${IMAGE_TAG}"
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

        stage('Claude PR review (advisory)') {
            // homelab-factory phase 6c: independent claude -p review posted on the Gitea PR.
            // Advisory: never fails the build (UNSTABLE at most, e.g. while credentials are missing).
            when { changeRequest() }
            environment {
                GITEA_URL        = 'http://192.168.1.62:9090'
                HF_REVIEW_BUDGET = '0.50'
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    withCredentials([
                        string(credentialsId: 'anthropic-api-key', variable: 'ANTHROPIC_API_KEY'),
                        string(credentialsId: 'gitea-factory-bot', variable: 'GITEA_TOKEN'),
                    ]) {
                        sh '''
                            docker run --rm \
                              -v "$WORKSPACE:/workspace" -w /workspace \
                              -e ANTHROPIC_API_KEY -e GITEA_TOKEN -e GITEA_URL \
                              -e CHANGE_ID -e CHANGE_TARGET -e GIT_URL -e BUILD_URL -e JOB_NAME -e BUILD_NUMBER -e JENKINS_URL \
                              -e HF_REVIEW_BUDGET -e NO_PROXY -e no_proxy \
                              "$REGISTRY/claude-runner:2.1.286-hf1" \
                              sh -c 'git config --global --add safe.directory /workspace && python3 /opt/hf/ci/pr_review.py'
                        '''
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'costs.jsonl,pr-review.result.json', allowEmptyArchive: true
                }
            }
        }

        stage('Push to Registry') {
            // Only reviewed code reaches the registry: master (or the legacy single-branch job).
            // Watchtower on Magua pulls :latest, so a PR build must never push it.
            when { expression { env.BRANCH_NAME == null || env.BRANCH_NAME == 'master' } }
            steps {
                echo "Pushing image to ${REGISTRY}..."
                sh "docker tag ${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG} ${REGISTRY}/${IMAGE_NAME}:latest"
                retry(3) { sh "docker push ${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}" }
                retry(3) { sh "docker push ${REGISTRY}/${IMAGE_NAME}:latest" }
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
        //                 -t ${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}-arm64 \
        //                 -t ${REGISTRY}/${IMAGE_NAME}:latest-arm64 \
        //                 .
        //         """
        //         sh "docker push ${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}-arm64"
        //         sh "docker push ${REGISTRY}/${IMAGE_NAME}:latest-arm64"
        //     }
        // }
    }

    post {
        always {
            sh 'rm -f test-results.xml coverage.xml || true'
            sh "docker rmi ${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG} || true"
            sh "docker volume rm cnds-sonar-${IMAGE_TAG} || true"
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
