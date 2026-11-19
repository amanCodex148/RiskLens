"""
Unit and Integration Tests for NLP Dialogue & Conversational Capabilities.
Tests fine-tuned 20x NLP model and support for common conversation:
- Greetings: 'hi', 'hello', 'hey', 'good morning', 'hey there'
- Help Requests: 'i need help', 'can you help me', 'guide me', 'support'
- Pleasantries: 'how are you', 'how is it going'
- Gratitude: 'thanks', 'thank you', 'appreciate it'
- Farewells: 'bye', 'goodbye', 'see you'
- Contraction & Slang Normalization: 'hiii', 'heyy', 'plz help'
- Composite queries & REST API integration.
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.engine.ai_nlp_engine import AiNlpEngine, AiNlpIntent
from backend.engine.ai_decision import AiDecisionSupportService
from backend.engine.ai_knowledge import ProjectKnowledgeAgent


class TestNlpConversation(unittest.TestCase):
    def setUp(self):
        self.nlp = AiNlpEngine()
        self.decision_service = AiDecisionSupportService()
        self.client = TestClient(app)

    def test_nlp_text_normalization(self):
        """Verifies contraction expansion and typo normalization."""
        norm_hi = self.nlp.normalize_text("hiiii!")
        self.assertEqual(norm_hi.lower(), "hi")

        norm_hey = self.nlp.normalize_text("heyy there")
        self.assertEqual(norm_hey.lower(), "hey there")

        norm_help = self.nlp.normalize_text("i'm stuck, plz help me")
        self.assertIn("i am", norm_help.lower())
        self.assertIn("please", norm_help.lower())

    def test_greetings_classification_and_response(self):
        """Verifies common greetings: hi, hello, hey, good morning."""
        for greeting in ["hi", "hello", "hey", "hey there", "good morning", "good evening", "howdy", "hiii"]:
            intent, conf, _ = self.nlp.classify_intent(greeting)
            self.assertEqual(intent, AiNlpIntent.GREETING, f"Failed for {greeting}")
            self.assertGreaterEqual(conf, 0.70)

            # Test response generation
            resp = self.nlp.generate_conversational_response(intent, greeting, user_name="Aman")
            self.assertEqual(resp["data"]["topic"], "conversational_greeting")
            self.assertIn("Hello", resp["response_markdown"])
            self.assertIn("Aman", resp["response_markdown"])
            self.assertTrue(len(resp["suggested_next_questions"]) >= 2)

    def test_help_requests_classification_and_response(self):
        """Verifies common help requests: i need help, help me, can you help me."""
        for help_query in ["i need help", "help", "help me", "can you help me", "can you help", "guide me"]:
            intent, conf, _ = self.nlp.classify_intent(help_query)
            self.assertEqual(intent, AiNlpIntent.HELP, f"Failed for {help_query}")
            self.assertGreaterEqual(conf, 0.70)

            resp = self.nlp.generate_conversational_response(intent, help_query)
            self.assertEqual(resp["data"]["topic"], "conversational_help")
            self.assertIn("How Can I Help You", resp["response_markdown"])
            self.assertIn("Risk Identification", resp["response_markdown"])

    def test_pleasantry_gratitude_farewell(self):
        """Verifies small talk, gratitude, and farewells."""
        # How are you
        intent, _, _ = self.nlp.classify_intent("how are you")
        self.assertEqual(intent, AiNlpIntent.PLEASANTRY)
        resp = self.nlp.generate_conversational_response(intent, "how are you")
        self.assertIn("doing great", resp["response_markdown"])

        # Thank you
        intent, _, _ = self.nlp.classify_intent("thank you so much")
        self.assertEqual(intent, AiNlpIntent.GRATITUDE)
        resp = self.nlp.generate_conversational_response(intent, "thank you")
        self.assertIn("welcome", resp["response_markdown"].lower())

        # Bye
        intent, _, _ = self.nlp.classify_intent("goodbye")
        self.assertEqual(intent, AiNlpIntent.FAREWELL)
        resp = self.nlp.generate_conversational_response(intent, "goodbye")
        self.assertIn("Goodbye", resp["response_markdown"])

    def test_composite_queries_route_to_domain(self):
        """Verifies composite queries (e.g. 'hi, what are our top 5 risks?') route to domain handlers."""
        # Query with greeting prefix followed by domain request
        agent = self.decision_service.knowledge_agent

        res1 = agent.answer_query("hi, what are our five most critical risks?")
        self.assertIn("Core Banking", res1["response_markdown"])

        res2 = agent.answer_query("hello, why is this risk rated high?")
        self.assertEqual(res2.get("data", {}).get("topic"), "risk_rating_causal_analysis")
        self.assertIn("Risk Rating", res2["response_markdown"])

    def test_conversational_queries_in_knowledge_agent(self):
        """Verifies ProjectKnowledgeAgent handles direct conversational inputs."""
        agent = self.decision_service.knowledge_agent

        # 1. Hi
        res_hi = agent.answer_query("hi")
        self.assertEqual(res_hi["data"]["topic"], "conversational_greeting")
        self.assertIn("Welcome to RiskLens AI", res_hi["response_markdown"])

        # 2. Hello
        res_hello = agent.answer_query("hello")
        self.assertEqual(res_hello["data"]["topic"], "conversational_greeting")

        # 3. Hey
        res_hey = agent.answer_query("hey")
        self.assertEqual(res_hey["data"]["topic"], "conversational_greeting")

        # 4. I need help
        res_help = agent.answer_query("i need help")
        self.assertEqual(res_help["data"]["topic"], "conversational_help")
        self.assertIn("How Can I Help You", res_help["response_markdown"])

    def test_rest_api_assistant_query_conversation(self):
        """Verifies POST /api/assistant/query endpoint with conversational messages."""
        # 1. Send 'hi'
        resp_hi = self.client.post("/api/assistant/query", json={"query": "hi"})
        self.assertEqual(resp_hi.status_code, 200)
        data_hi = resp_hi.json()
        self.assertEqual(data_hi["data"]["topic"], "conversational_greeting")
        self.assertIn("Welcome to RiskLens AI", data_hi["response_markdown"])

        # 2. Send 'i need help'
        resp_help = self.client.post("/api/assistant/query", json={"query": "i need help"})
        self.assertEqual(resp_help.status_code, 200)
        data_help = resp_help.json()
        self.assertEqual(data_help["data"]["topic"], "conversational_help")

        # 3. Send 'how are you'
        resp_how = self.client.post("/api/assistant/query", json={"query": "how are you"})
        self.assertEqual(resp_how.status_code, 200)
        data_how = resp_how.json()
        self.assertEqual(data_how["data"]["topic"], "conversational_pleasantry")

    def test_100_epochs_retraining_and_convergence(self):
        """Verifies that 100-epoch neural gradient descent training converges with 20x dataset."""
        telemetry = self.nlp.retrain(epochs=100)
        self.assertEqual(telemetry["epochs_trained"], 100)
        self.assertGreaterEqual(telemetry["dataset_size"], 1000)
        self.assertEqual(len(telemetry["loss_history"]), 100)
        self.assertLess(telemetry["final_loss"], telemetry["initial_loss"])
        self.assertGreaterEqual(telemetry["loss_reduction_pct"], 75.0)
        self.assertGreaterEqual(telemetry["final_accuracy"], 95.0)
        self.assertTrue(telemetry["converged"])

    def test_user_query_retrain_100_times_20x(self):
        """Verifies that user request 'retrain it 100 times and fine tune 20x times more' executes cleanly."""
        agent = self.decision_service.knowledge_agent
        res = agent.answer_query(
            "retrain it 100 times and fine tune 20x times more",
            user_email="admin@risklens.local"
        )
        self.assertEqual(res.get("data", {}).get("topic"), "model_retraining_telemetry")
        self.assertIn("AI Model Retraining", res["response_markdown"])
        self.assertIn("100 Epochs", res["response_markdown"])
        self.assertIn("20×", res["response_markdown"])
        self.assertIn("Categorical Loss", res["response_markdown"])

    def test_rest_api_retrain_and_model_info_endpoints(self):
        """Verifies REST API endpoints POST /api/assistant/nlp/retrain and GET /api/assistant/nlp/model-info."""
        # 1. Retrain endpoint
        res_retrain = self.client.post("/api/assistant/nlp/retrain", json={"epochs": 100})
        self.assertEqual(res_retrain.status_code, 200)
        retrain_data = res_retrain.json()
        self.assertEqual(retrain_data["status"], "success")
        self.assertEqual(retrain_data["telemetry"]["epochs_trained"], 100)
        self.assertIn(retrain_data["telemetry"]["fine_tune_factor"], ["20x", "400x"])

        # 2. Model info endpoint
        res_info = self.client.get("/api/assistant/nlp/model-info")
        self.assertEqual(res_info.status_code, 200)
        info_data = res_info.json()
        self.assertIn("Multi-Class Neural Softmax", info_data["model_type"])
        self.assertGreaterEqual(info_data["feature_vocabulary_size"], 500)
        self.assertGreaterEqual(info_data["num_intent_classes"], 20)
        self.assertIn(info_data["fine_tune_factor"], ["20x", "400x"])


if __name__ == "__main__":
    unittest.main()
