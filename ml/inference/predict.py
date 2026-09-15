from backend.app.ml.inference import run_inference
def predict_flow(model_name: str, df):
    return run_inference(model_name, df)
